package encryptionconfig

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"

	druidapicommon "github.com/gardener/etcd-druid/api/common"
	v1alpha1config "github.com/gardener/etcd-druid/api/config/v1alpha1"
	"github.com/gardener/etcd-druid/api/config/v1alpha1/validation"
	"github.com/gardener/etcd-druid/api/core/v1alpha1"
	druidv1alpha1 "github.com/gardener/etcd-druid/api/core/v1alpha1"
	"github.com/gardener/etcd-druid/internal/common"
	"github.com/gardener/etcd-druid/internal/component"
	druiderr "github.com/gardener/etcd-druid/internal/errors"
	"github.com/gardener/etcd-druid/internal/utils"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/yaml"
)

const (
	// ErrGetSecret indicates an error in getting the secret resource.
	ErrGetSecret druidapicommon.ErrorCode = "ERR_GET_SECRET"
	// ErrSyncSecret indicates an error in syncing the secret resource.
	ErrSyncSecret druidapicommon.ErrorCode = "ERR_SYNC_SECRET"
	// ErrDeleteSecret indicates an error in deleting the secret resource.
	ErrDeleteSecret druidapicommon.ErrorCode = "ERR_DELETE_SECRET"

	// DataKeyEncryptionProvider is the key in a secret data holding the encryption provider.
	DataKeyEncryptionProvider = "provider"
	// DataKeyEncryptionKeyName is the key in a secret data holding the key.
	DataKeyEncryptionKeyName = "key"
	// DataKeyEncryptionSecret is the key in a secret data holding the secret.
	DataKeyEncryptionSecret = "secret"
)

type _resource struct {
	client client.Client
}

// New returns a new configmap component operator.
func New(client client.Client) component.Operator {
	return &_resource{
		client: client,
	}
}

func (r *_resource) GetExistingResourceNames(ctx component.OperatorContext, etcdObjMeta metav1.ObjectMeta) ([]string, error) {
	resourceNames := make([]string, 0, 1)
	objKey := getObjectKey(etcdObjMeta)
	objMeta := &metav1.PartialObjectMetadata{}
	objMeta.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("Secret"))
	if err := r.client.Get(ctx, objKey, objMeta); err != nil {
		if errors.IsNotFound(err) {
			return resourceNames, nil
		}
		return nil, druiderr.WrapError(err,
			ErrGetSecret,
			component.OperationGetExistingResourceNames,
			fmt.Sprintf("Error getting encryption secret: %v for etcd: %v", objKey, druidv1alpha1.GetNamespaceName(etcdObjMeta)))
	}
	if metav1.IsControlledBy(objMeta, &etcdObjMeta) {
		resourceNames = append(resourceNames, objMeta.Name)
	}
	return resourceNames, nil
}

func (_ *_resource) PreSync(ctx component.OperatorContext, etcd *v1alpha1.Etcd) error {
	return nil
}

func (r *_resource) Sync(ctx component.OperatorContext, etcd *v1alpha1.Etcd) error {
	config := v1alpha1config.EncryptionConfiguration{
		TypeMeta: metav1.TypeMeta{
			Kind:       "EncryptionConfiguration",
			APIVersion: v1alpha1config.SchemeGroupVersion.String(),
		},
	}

	for _, secretRef := range etcd.Spec.Backup.EncryptionKeyRefs {
		secret := corev1.Secret{}

		if err := r.client.Get(ctx, types.NamespacedName{
			Namespace: secretRef.Namespace,
			Name:      secretRef.Name,
		}, &secret); err != nil {
			return fmt.Errorf("unable to read encryption secret: %w", err)
		}

		if secret.Data == nil {
			return fmt.Errorf("secret data is nil")
		}

		key := v1alpha1config.EncryptionKey{
			Name:   string(secret.Data[DataKeyEncryptionKeyName]),
			Secret: []byte(base64.RawStdEncoding.EncodeToString(secret.Data[DataKeyEncryptionSecret])),
		}

		switch provider := secret.Data[DataKeyEncryptionProvider]; v1alpha1config.EncryptionProviderType(provider) {
		case v1alpha1config.EncryptionProviderTypeAESGCM:
			if idx := slices.IndexFunc(config.Providers, func(p v1alpha1config.EncryptionProvider) bool {
				return p.AesGcmProvider != nil
			}); idx >= 0 {
				config.Providers[idx].AesGcmProvider.Keys = append(config.Providers[idx].AesGcmProvider.Keys, key)
			} else {
				config.Providers = append(config.Providers, v1alpha1config.EncryptionProvider{
					AesGcmProvider: &v1alpha1config.EncryptionProviderAesGCM{
						Keys: []v1alpha1config.EncryptionKey{key},
					},
				})
			}

		case v1alpha1config.EncryptionProviderTypeAESCBC:
			if idx := slices.IndexFunc(config.Providers, func(p v1alpha1config.EncryptionProvider) bool {
				return p.AesCbcProvider != nil
			}); idx >= 0 {
				config.Providers[idx].AesCbcProvider.Keys = append(config.Providers[idx].AesCbcProvider.Keys, key)
			} else {
				config.Providers = append(config.Providers, v1alpha1config.EncryptionProvider{
					AesCbcProvider: &v1alpha1config.EncryptionProviderAesCbc{
						Keys: []v1alpha1config.EncryptionKey{key},
					},
				})
			}

		default:
			return fmt.Errorf("provider not supported (yet): %s", provider)
		}
	}

	if errList := validation.ValidateEncryptionConfiguration(&config); len(errList) > 0 {
		return fmt.Errorf("error constructing encryption config: %w", errList.ToAggregate())
	}

	encoded, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("unable to encode encryption config: %w", err)
	}

	secret := emptySecret(getObjectKey(etcd.ObjectMeta))
	result, err := controllerutil.CreateOrPatch(ctx, r.client, secret, func() error {
		secret.Data = map[string][]byte{
			"config.yaml": encoded,
		}
		secret.Labels = getLabels(etcd)
		secret.OwnerReferences = []metav1.OwnerReference{druidv1alpha1.GetAsOwnerReference(etcd.ObjectMeta)}

		return nil
	})
	if err != nil {
		return druiderr.WrapError(err,
			ErrSyncSecret,
			component.OperationSync,
			fmt.Sprintf("Error during create or update of encryption secret for etcd: %v", druidv1alpha1.GetNamespaceName(etcd.ObjectMeta)))
	}
	checkSum, err := computeCheckSum(secret)
	if err != nil {
		return druiderr.WrapError(err,
			ErrSyncSecret,
			component.OperationSync,
			fmt.Sprintf("Error when computing CheckSum for encryption secret for etcd: %v", druidv1alpha1.GetNamespaceName(etcd.ObjectMeta)))
	}
	ctx.Data[common.CheckSumKeyEncryptionSecret] = checkSum
	ctx.Logger.Info("synced", "component", "encryptionconfig", "name", secret.Name, "result", result)
	return nil
}

func (r *_resource) TriggerDelete(ctx component.OperatorContext, etcdObjMeta metav1.ObjectMeta) error {
	objectKey := getObjectKey(etcdObjMeta)
	ctx.Logger.Info("Triggering deletion of ConfigMap", "objectKey", objectKey)
	if err := r.client.Delete(ctx, emptySecret(objectKey)); err != nil {
		if errors.IsNotFound(err) {
			ctx.Logger.Info("No encryption secret found, Deletion is a No-Op", "objectKey", objectKey)
			return nil
		}
		return druiderr.WrapError(
			err,
			ErrDeleteSecret,
			component.OperationTriggerDelete,
			"Failed to delete encryption secret",
		)
	}
	ctx.Logger.Info("deleted", "component", "secret", "objectKey", objectKey)
	return nil
}

func getObjectKey(obj metav1.ObjectMeta) client.ObjectKey {
	return client.ObjectKey{
		Name:      druidv1alpha1.GetEncryptionConfigSecretName(obj),
		Namespace: obj.Namespace,
	}
}

func emptySecret(objectKey client.ObjectKey) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      objectKey.Name,
			Namespace: objectKey.Namespace,
		},
	}
}

func computeCheckSum(secret *corev1.Secret) (string, error) {
	jsonData, err := json.Marshal(secret.Data)
	if err != nil {
		return "", err
	}
	return utils.ComputeSHA256Hex(jsonData), nil
}

func getLabels(etcd *druidv1alpha1.Etcd) map[string]string {
	cmLabels := map[string]string{
		druidv1alpha1.LabelComponentKey: common.ComponentNameConfigMap,
		druidv1alpha1.LabelAppNameKey:   druidv1alpha1.GetConfigMapName(etcd.ObjectMeta),
	}
	return utils.MergeMaps(druidv1alpha1.GetDefaultLabels(etcd.ObjectMeta), cmLabels)
}
