package validation

import (
	"encoding/base64"
	"testing"

	druidconfigv1alpha1 "github.com/gardener/etcd-druid/api/config/v1alpha1"

	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"

	gomegatypes "github.com/onsi/gomega/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestValidateEncryptionConfiguration(t *testing.T) {
	var (
		validEncodedKey = base64.RawStdEncoding.EncodeToString([]byte("abcdefghijklmnopqrstuvwxyz123456"))
		malformedKey    = []byte("<>")
		tooLongKey      = base64.RawStdEncoding.EncodeToString([]byte("abcdefghijklmnopqrstuvwxyz1234567890"))
	)

	tests := []struct {
		name    string
		config  *druidconfigv1alpha1.EncryptionConfiguration
		matcher gomegatypes.GomegaMatcher
	}{
		{
			name:   "nil config",
			config: nil,
		},
		{
			name:   "empty config",
			config: &druidconfigv1alpha1.EncryptionConfiguration{},
		},
		{
			name: "minimum valid aes gcm config",
			config: &druidconfigv1alpha1.EncryptionConfiguration{
				Providers: []druidconfigv1alpha1.EncryptionProvider{
					{
						AesGcmProvider: &druidconfigv1alpha1.EncryptionProviderAesGCM{
							Keys: []druidconfigv1alpha1.EncryptionKey{
								{
									Name:   "key1",
									Secret: []byte(validEncodedKey),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "minimum valid aes cbc config",
			config: &druidconfigv1alpha1.EncryptionConfiguration{
				Providers: []druidconfigv1alpha1.EncryptionProvider{
					{
						AesCbcProvider: &druidconfigv1alpha1.EncryptionProviderAesCbc{
							Keys: []druidconfigv1alpha1.EncryptionKey{
								{
									Name:   "key1",
									Secret: []byte(validEncodedKey),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "valid aes gcm config",
			config: &druidconfigv1alpha1.EncryptionConfiguration{
				Providers: []druidconfigv1alpha1.EncryptionProvider{
					{
						AesGcmProvider: &druidconfigv1alpha1.EncryptionProviderAesGCM{
							Keys: []druidconfigv1alpha1.EncryptionKey{
								{
									Name:   "key1",
									Secret: []byte(validEncodedKey),
								},
								{
									Name:   "key2",
									Secret: []byte(validEncodedKey),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "duplicate key names",
			config: &druidconfigv1alpha1.EncryptionConfiguration{
				Providers: []druidconfigv1alpha1.EncryptionProvider{
					{
						AesGcmProvider: &druidconfigv1alpha1.EncryptionProviderAesGCM{
							Keys: []druidconfigv1alpha1.EncryptionKey{
								{
									Name:   "key1",
									Secret: []byte(validEncodedKey),
								},
								{
									Name:   "key1",
									Secret: []byte(validEncodedKey),
								},
							},
						},
					},
				},
			},
			matcher: ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{"Type": Equal(field.ErrorTypeDuplicate), "Field": Equal("providers[0].aesgcm[1].name"), "BadValue": Equal("key1")}))),
		},
		{
			name: "malformed key",
			config: &druidconfigv1alpha1.EncryptionConfiguration{
				Providers: []druidconfigv1alpha1.EncryptionProvider{
					{
						AesGcmProvider: &druidconfigv1alpha1.EncryptionProviderAesGCM{
							Keys: []druidconfigv1alpha1.EncryptionKey{
								{
									Name:   "key1",
									Secret: []byte(malformedKey),
								},
							},
						},
					},
				},
			},
			matcher: ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{"Type": Equal(field.ErrorTypeInvalid), "Field": Equal("providers[0].aesgcm[0].secret"), "Detail": Equal("secret cannot be base64 decoded: illegal base64 data at input byte 0")}))),
		},
		{
			name: "too long key",
			config: &druidconfigv1alpha1.EncryptionConfiguration{
				Providers: []druidconfigv1alpha1.EncryptionProvider{
					{
						AesGcmProvider: &druidconfigv1alpha1.EncryptionProviderAesGCM{
							Keys: []druidconfigv1alpha1.EncryptionKey{
								{
									Name:   "key1",
									Secret: []byte(tooLongKey),
								},
							},
						},
					},
				},
			},
			matcher: ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{"Type": Equal(field.ErrorTypeInvalid), "Field": Equal("providers[0].aesgcm[0].secret"), "Detail": Equal("secret must have 32 bytes, but has 36")}))),
		},
		{
			name: "no keys",
			config: &druidconfigv1alpha1.EncryptionConfiguration{
				Providers: []druidconfigv1alpha1.EncryptionProvider{
					{
						AesGcmProvider: &druidconfigv1alpha1.EncryptionProviderAesGCM{
							Keys: []druidconfigv1alpha1.EncryptionKey{},
						},
					},
				},
			},
			matcher: ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{"Type": Equal(field.ErrorTypeInvalid), "Field": Equal("providers[0].aesgcm"), "Detail": Equal("at least one key must be provided")}))),
		},
		{
			name: "no provider set",
			config: &druidconfigv1alpha1.EncryptionConfiguration{
				Providers: []druidconfigv1alpha1.EncryptionProvider{
					{},
				},
			},
			matcher: ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{"Type": Equal(field.ErrorTypeInvalid), "Field": Equal("providers[0]"), "Detail": Equal("exactly one provider type must be specified")}))),
		},
		{
			name: "two providers set in one provider",
			config: &druidconfigv1alpha1.EncryptionConfiguration{
				Providers: []druidconfigv1alpha1.EncryptionProvider{
					{
						AesGcmProvider: &druidconfigv1alpha1.EncryptionProviderAesGCM{
							Keys: []druidconfigv1alpha1.EncryptionKey{
								{
									Name:   "key1",
									Secret: []byte(validEncodedKey),
								},
							},
						},
						AesCbcProvider: &druidconfigv1alpha1.EncryptionProviderAesCbc{
							Keys: []druidconfigv1alpha1.EncryptionKey{
								{
									Name:   "key1",
									Secret: []byte(validEncodedKey),
								},
							},
						},
					},
				},
			},
			matcher: ConsistOf(PointTo(MatchFields(IgnoreExtras, Fields{"Type": Equal(field.ErrorTypeInvalid), "Field": Equal("providers[0]"), "Detail": Equal("exactly one provider type must be specified")}))),
		},
		{
			name: "two providers set",
			config: &druidconfigv1alpha1.EncryptionConfiguration{
				Providers: []druidconfigv1alpha1.EncryptionProvider{
					{
						AesGcmProvider: &druidconfigv1alpha1.EncryptionProviderAesGCM{
							Keys: []druidconfigv1alpha1.EncryptionKey{
								{
									Name:   "key1",
									Secret: []byte(validEncodedKey),
								},
							},
						},
					},
					{
						AesCbcProvider: &druidconfigv1alpha1.EncryptionProviderAesCbc{
							Keys: []druidconfigv1alpha1.EncryptionKey{
								{
									Name:   "key1",
									Secret: []byte(validEncodedKey),
								},
							},
						},
					},
				},
			},
		},
	}

	// fldPath := field.NewPath("leaderElection")

	g := NewWithT(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualErrList := ValidateEncryptionConfiguration(tt.config)

			if tt.matcher != nil {
				g.Expect(actualErrList).To(tt.matcher)
			} else {
				g.Expect(actualErrList).To(BeEmpty())
			}
		})
	}
}
