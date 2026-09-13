/*
Copyright The k3sm Authors.

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

package podlogs

import (
	"fmt"
	"net/url"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/conversion"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

// The query-string → v1.PodLogOptions decoder.
//
// Upstream's kubelet reaches this through legacyscheme.ParameterCodec, whose
// scheme is built by k8s.io/kubernetes/pkg/apis/core/install and therefore
// carries the GENERATED Convert_url_Values_To_v1_PodLogOptions. That package is
// inside the kubernetes monorepo and is not importable from here, and
// client-go's own kubernetes/scheme registers the TYPES but not that conversion
// — a DecodeParameters against it fails every non-empty query with "unknown
// conversion", which is a 400 on every `kubectl logs --tail`.
//
// So the conversion is hand-ported below, field for field, from the generated
// function, on a package-private scheme. It is deliberately a port rather than
// an ad-hoc parser: the decoder is what decides whether `tailLines=0` arrives as
// a pointer to zero or as unset, and re-deriving that by hand from the query
// string is how a reimplementation drifts from the API it claims to serve.

var (
	// podLogScheme carries corev1's types plus the one conversion below.
	podLogScheme = runtime.NewScheme()
	// podLogParameterCodec decodes a kubelet /containerLogs query string.
	podLogParameterCodec runtime.ParameterCodec
)

// init registers the corev1 types and the url.Values conversion. A registration
// failure here is a programming error that would make every log request fail, so
// it is fatal at start rather than per request — the standard apimachinery idiom.
func init() {
	utilruntime.Must(corev1.AddToScheme(podLogScheme))
	metav1.AddToGroupVersion(podLogScheme, corev1.SchemeGroupVersion)
	utilruntime.Must(podLogScheme.AddConversionFunc((*url.Values)(nil), (*corev1.PodLogOptions)(nil),
		func(a, b any, scope conversion.Scope) error {
			in, ok := a.(*url.Values)
			if !ok {
				return fmt.Errorf("podlogs: conversion source is %T, want *url.Values", a)
			}
			out, ok := b.(*corev1.PodLogOptions)
			if !ok {
				return fmt.Errorf("podlogs: conversion target is %T, want *corev1.PodLogOptions", b)
			}
			return convertURLValuesToPodLogOptions(in, out, scope)
		}))
	podLogParameterCodec = runtime.NewParameterCodec(podLogScheme)
}

// DecodePodLogOptions decodes a /containerLogs query string into the kubelet's
// v1.PodLogOptions, with upstream's exact semantics for every field.
func DecodePodLogOptions(query url.Values, out *corev1.PodLogOptions) error {
	return podLogParameterCodec.DecodeParameters(query, corev1.SchemeGroupVersion, out)
}

// convertURLValuesToPodLogOptions is the hand port of the generated
// Convert_url_Values_To_v1_PodLogOptions (k8s.io/kubernetes
// pkg/apis/core/v1/zz_generated.conversion.go, Apache-2.0).
//
// The else-branches that clear each field are the generated function's, not
// defensive noise: DecodeParameters may be handed a reused struct, and an
// absent parameter means "unset", never "keep whatever was there".
func convertURLValuesToPodLogOptions(in *url.Values, out *corev1.PodLogOptions, s conversion.Scope) error {
	values := map[string][]string(*in)
	if v, ok := values["container"]; ok && len(v) > 0 {
		if err := runtime.Convert_Slice_string_To_string(&v, &out.Container, s); err != nil {
			return err
		}
	} else {
		out.Container = ""
	}
	if v, ok := values["follow"]; ok && len(v) > 0 {
		if err := runtime.Convert_Slice_string_To_bool(&v, &out.Follow, s); err != nil {
			return err
		}
	} else {
		out.Follow = false
	}
	if v, ok := values["previous"]; ok && len(v) > 0 {
		if err := runtime.Convert_Slice_string_To_bool(&v, &out.Previous, s); err != nil {
			return err
		}
	} else {
		out.Previous = false
	}
	if v, ok := values["sinceSeconds"]; ok && len(v) > 0 {
		if err := runtime.Convert_Slice_string_To_Pointer_int64(&v, &out.SinceSeconds, s); err != nil {
			return err
		}
	} else {
		out.SinceSeconds = nil
	}
	if v, ok := values["sinceTime"]; ok && len(v) > 0 {
		if err := metav1.Convert_Slice_string_To_Pointer_v1_Time(&v, &out.SinceTime, s); err != nil {
			return err
		}
	} else {
		out.SinceTime = nil
	}
	if v, ok := values["timestamps"]; ok && len(v) > 0 {
		if err := runtime.Convert_Slice_string_To_bool(&v, &out.Timestamps, s); err != nil {
			return err
		}
	} else {
		out.Timestamps = false
	}
	if v, ok := values["tailLines"]; ok && len(v) > 0 {
		if err := runtime.Convert_Slice_string_To_Pointer_int64(&v, &out.TailLines, s); err != nil {
			return err
		}
	} else {
		out.TailLines = nil
	}
	if v, ok := values["limitBytes"]; ok && len(v) > 0 {
		if err := runtime.Convert_Slice_string_To_Pointer_int64(&v, &out.LimitBytes, s); err != nil {
			return err
		}
	} else {
		out.LimitBytes = nil
	}
	if v, ok := values["insecureSkipTLSVerifyBackend"]; ok && len(v) > 0 {
		if err := runtime.Convert_Slice_string_To_bool(&v, &out.InsecureSkipTLSVerifyBackend, s); err != nil {
			return err
		}
	} else {
		out.InsecureSkipTLSVerifyBackend = false
	}
	if v, ok := values["stream"]; ok && len(v) > 0 {
		// apimachinery has no Slice_string_To_Pointer_string helper, so the one
		// line the generator would have emitted is written out. The field is
		// still DECODED even though gate-off validation rejects any value for
		// it — the 422 is the validator's verdict, and a decoder that silently
		// dropped the parameter would make that verdict unreachable.
		str := v[0]
		out.Stream = &str
	} else {
		out.Stream = nil
	}
	return nil
}
