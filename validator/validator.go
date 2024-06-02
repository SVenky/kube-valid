package validator

import (
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/SVenky/kube-valid/util"
	"github.com/go-logr/logr"
	"github.com/hashicorp/go-multierror"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	structuralschema "k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	structuraldefaulting "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/defaulting"
	structurallisttype "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/listtype"
	schemaobjectmeta "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/objectmeta"
	sprune "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/pruning"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	kyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/kube-openapi/pkg/validation/validate"
	ctrl "sigs.k8s.io/controller-runtime"
)

var (
	vlog logr.Logger
)

// Validator returns a new validator for custom resources
type Validator struct {
	Client      dynamic.Interface
	DClient     *discovery.DiscoveryClient
	byGvk       map[schema.GroupVersionKind]*validate.SchemaValidator
	structural  map[schema.GroupVersionKind]*structuralschema.Structural
	SkipMissing bool //used to skip validation of missing gvk
	rw          sync.RWMutex
}

// ValidateCustomResourceYAML - takes yaml input and validates each of CR in it.
func (v *Validator) ValidateCustomResourceYAML(data string) error {
	v.rw.RLock()
	defer v.rw.RUnlock()
	var errs *multierror.Error
	for _, item := range util.SplitYamlString(data) {
		obj := &unstructured.Unstructured{}
		if err := kyaml.Unmarshal([]byte(item), obj); err != nil {
			return err
		}
		_, err := v.ValidateCustomResource(obj, false)
		errs = multierror.Append(errs, err)
	}
	return errs.ErrorOrNil()
}

// ValidateCustomResource - Validates a CR object against the schema validator and structural schema
func (v *Validator) ValidateCustomResource(o runtime.Object, skipCluster bool) (field.ErrorList, error) {
	v.rw.RLock()
	defer v.rw.RUnlock()
	content, err := runtime.DefaultUnstructuredConverter.ToUnstructured(o)
	if err != nil {
		return nil, err
	}
	un := &unstructured.Unstructured{Object: content}
	gvk := un.GroupVersionKind()
	vd, ok := v.byGvk[gvk]
	vstructural, ok := v.structural[gvk]
	if !ok {
		if v.SkipMissing {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to validate type %v: no structural schema found", un.GroupVersionKind())
	} else {
		if obj, ok := un.Object["spec"]; !ok || obj == nil {
			un.Object["spec"] = make(map[string]interface{})
		}
	}
	//fill the default values using the structural from the map we preserved
	structuraldefaulting.Default(un.Object, vstructural)
	opts := schemaobjectmeta.CoerceOptions{ReturnUnknownFieldPaths: true}
	//validate unknown fields in the resource type and object meta
	if err, unknownFlds := schemaobjectmeta.CoerceWithOptions(nil, un.Object, vstructural, true, opts); err != nil || len(unknownFlds) != 0 {
		var errs field.ErrorList
		if err != nil {
			vlog.Info("schema metadata error", err)
			errs = field.ErrorList{err}
		} else {
			errs = make(field.ErrorList, len(unknownFlds))
			for i, uf := range unknownFlds {
				errs[i] = field.Invalid(field.NewPath(uf), nil, "unsupported CR metadata field")
			}
		}
		return errs, fmt.Errorf("unknown fields error: %v/%v/%v: %v, unknown fields: %v", un.GroupVersionKind().Kind, un.GetName(), un.GetNamespace(), err, unknownFlds)
	}
	//validate the resource type and object meta
	if errs := schemaobjectmeta.Validate(nil, un.Object, vstructural, true); errs != nil {
		return errs, fmt.Errorf("object meta error: %v/%v/%v: %v", un.GroupVersionKind().Kind, un.GetName(), un.GetNamespace(), errs.ToAggregate())
	}
	//validate the sets and maps
	if errs := structurallisttype.ValidateListSetsAndMaps(nil, vstructural, un.Object); errs != nil {
		return errs, fmt.Errorf("list sets and maps error: %v/%v/%v: %v", un.GroupVersionKind().Kind, un.GetName(), un.GetNamespace(), errs.ToAggregate())
	}
	//validate unknown fields in the resource spec
	//sprune.Prune(un.Object, vstructural, true)
	unknownfldOpts := structuralschema.UnknownFieldPathOptions{
		TrackUnknownFieldPaths: true,
	}
	if unknownFldArr := sprune.PruneWithOptions(un.Object, vstructural, true, unknownfldOpts); len(unknownFldArr) > 0 {
		errs := make(field.ErrorList, len(unknownFldArr))
		for i, uf := range unknownFldArr {
			errs[i] = field.Invalid(field.NewPath(uf), nil, "unsupported CR spec field")
		}

		return errs, fmt.Errorf("unknown fields in spec error : %v/%v/%v: %v", un.GroupVersionKind().Kind, un.GetName(), un.GetNamespace(), unknownFldArr)
	}
	//custom resource against the schema from gvkmap
	if errs := validation.ValidateCustomResource(nil, un.Object, vd); errs != nil {
		return errs, fmt.Errorf("data error : %v/%v/%v: %v", un.GroupVersionKind().Kind, un.GetName(), un.GetNamespace(), errs.ToAggregate())
	}
	return nil, nil
}

func (v *Validator) AddCRDs(crds ...apiextensions.CustomResourceDefinition) error {
	v.rw.Lock()
	defer v.rw.Unlock()
	for _, crd := range crds {
		versions := crd.Spec.Versions
		if len(versions) == 0 {
			versions = []apiextensions.CustomResourceDefinitionVersion{{Name: crd.Spec.Version}} // nolint: staticcheck
		}
		for _, ver := range versions {
			gvk := schema.GroupVersionKind{
				Group:   crd.Spec.Group,
				Version: ver.Name,
				Kind:    crd.Spec.Names.Kind,
			}
			crdSchema := ver.Schema
			if crdSchema == nil {
				crdSchema = crd.Spec.Validation
			}
			if crdSchema == nil {
				return fmt.Errorf("crd did not have validation defined")
			}
			schemaValidator, _, err := validation.NewSchemaValidator(crdSchema)
			if err != nil {
				return err
			}
			structural, err := structuralschema.NewStructural(crdSchema.OpenAPIV3Schema)
			if err != nil {
				return err
			}
			v.byGvk[gvk] = schemaValidator
			v.structural[gvk] = structural
		}
	}
	return nil
}

func NewValidatorFromFiles(files ...string) (*Validator, error) {
	crds := []apiextensions.CustomResourceDefinition{}
	closers := make([]io.Closer, 0, len(files))
	defer func() {
		for _, closer := range closers {
			closer.Close()
		}
	}()
	for _, file := range files {
		data, err := os.Open(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read input yaml file: %v", err)
		}
		closers = append(closers, data)
		yamlDecoder := kyaml.NewYAMLOrJSONDecoder(data, 512*1024)
		for {
			un := &unstructured.Unstructured{}
			err = yamlDecoder.Decode(&un)
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			crd, err := ExtractCRDFromUnstructured(un)
			if err != nil {
				return nil, err
			}
			crds = append(crds, *crd)
		}
	}
	return NewValidatorFromCRDs(crds...)
}

func ExtractCRDFromUnstructured(un *unstructured.Unstructured) (*apiextensions.CustomResourceDefinition, error) {
	crd := &apiextensions.CustomResourceDefinition{}
	switch un.GroupVersionKind() {
	case schema.GroupVersionKind{
		Group:   "apiextensions.k8s.io",
		Version: "v1",
		Kind:    "CustomResourceDefinition",
	}:
		crdv1 := apiextensionsv1.CustomResourceDefinition{}
		if err := runtime.DefaultUnstructuredConverter.
			FromUnstructured(un.UnstructuredContent(), &crdv1); err != nil {
			return nil, err
		}
		if err := apiextensionsv1.Convert_v1_CustomResourceDefinition_To_apiextensions_CustomResourceDefinition(&crdv1, crd, nil); err != nil {
			return nil, err
		}
	case schema.GroupVersionKind{
		Group:   "apiextensions.k8s.io",
		Version: "v1beta1",
		Kind:    "CustomResourceDefinition",
	}:
		crdv1beta1 := apiextensionsv1beta1.CustomResourceDefinition{}
		if err := runtime.DefaultUnstructuredConverter.
			FromUnstructured(un.UnstructuredContent(), &crdv1beta1); err != nil {
			return nil, err
		}
		if err := apiextensionsv1beta1.Convert_v1beta1_CustomResourceDefinition_To_apiextensions_CustomResourceDefinition(&crdv1beta1, crd, nil); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown CRD type: %v", un.GroupVersionKind())
	}
	return crd, nil
}

func NewValidatorFromCRDs(crds ...apiextensions.CustomResourceDefinition) (*Validator, error) {
	vlog = ctrl.Log.WithName("validator")
	var err error
	v := &Validator{
		byGvk:      map[schema.GroupVersionKind]*validate.SchemaValidator{},
		structural: map[schema.GroupVersionKind]*structuralschema.Structural{},
	}
	err = v.AddCRDs(crds...)
	if err != nil {
		return nil, err
	}
	for _, crd := range crds {
		versions := crd.Spec.Versions
		if len(versions) == 0 {
			versions = []apiextensions.CustomResourceDefinitionVersion{{Name: crd.Spec.Version}} // nolint: staticcheck
		}
		for _, ver := range versions {
			gvk := schema.GroupVersionKind{
				Group:   crd.Spec.Group,
				Version: ver.Name,
				Kind:    crd.Spec.Names.Kind,
			}
			crdSchema := ver.Schema
			if crdSchema == nil {
				crdSchema = crd.Spec.Validation
			}
			if crdSchema == nil {
				return nil, fmt.Errorf("crd did not have validation defined")
			}
			schemaValidator, _, err := validation.NewSchemaValidator(crdSchema)
			if err != nil {
				return nil, err
			}
			structural, err := structuralschema.NewStructural(crdSchema.OpenAPIV3Schema)
			if err != nil {
				return nil, err
			}
			v.byGvk[gvk] = schemaValidator
			v.structural[gvk] = structural
		}
	}
	return v, nil
}
