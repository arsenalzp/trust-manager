/*
Copyright 2024 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package webhook

import (
	"context"
	"fmt"
	"hash/crc32"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// validator validates against trust.cert-manager.io resources.
type mutator struct {
	log logr.Logger
}

var _ admission.CustomDefaulter = &mutator{}

// Default mutator is neeed to set default values
// to our Bundle.
// Only password hash fields are mutated so far.
func (m *mutator) Default(ctx context.Context, obj runtime.Object) error {
	bundle, ok := obj.(*trustapi.Bundle)
	if !ok {
		return fmt.Errorf("expected a Bundle, but got a %T", obj)
	}

	if bundle.Spec.Target.AdditionalFormats == nil {
		return nil
	}

	var crcTable = crc32.MakeTable(32)
	var crc = crc32.New(crcTable)

	if bundle.Spec.Target.AdditionalFormats.JKS != nil &&
		bundle.Spec.Target.AdditionalFormats.JKS.PasswordHash == nil {
		m.log.Info("starting mutating JKS password hash")
		crc.Reset()
		crc.Write([]byte(*bundle.Spec.Target.AdditionalFormats.JKS.Password))
		bundle.Spec.Target.AdditionalFormats.JKS.PasswordHash = ptr.To(crc.Sum32())
	}

	if bundle.Spec.Target.AdditionalFormats.PKCS12 != nil &&
		bundle.Spec.Target.AdditionalFormats.PKCS12.PasswordHash == nil {
		m.log.Info("starting mutating PKCS12 password hash")
		crc.Reset()
		crc.Write([]byte(*bundle.Spec.Target.AdditionalFormats.PKCS12.Password))
		bundle.Spec.Target.AdditionalFormats.PKCS12.PasswordHash = ptr.To(crc.Sum32())
	}

	return nil
}
