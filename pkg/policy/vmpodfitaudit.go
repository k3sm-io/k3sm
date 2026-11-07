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

package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/google/cel-go/cel"
	celtypes "github.com/google/cel-go/common/types"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	plugincel "k8s.io/apiserver/pkg/admission/plugin/cel"
	"k8s.io/apiserver/pkg/admission/plugin/webhook/matchconditions"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/cel/environment"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// ErrVMPodFitRefused is returned by AuditVMPodFit, after the report is written, when
// at least one vm object is refused (or cannot be evaluated, which the policy's
// failurePolicy Fail also turns into a refusal). An input error is any other error.
var ErrVMPodFitRefused = errors.New("vm pod fit audit: at least one object is refused")

// AuditVMPodFit reads the JSON of "kubectl get pods,deploy,sts,ds,rs,job,cronjob -A
// -o json" (a List, or one object), keeps the objects whose pod spec names the vm
// RuntimeClass, and judges each as a Pod CREATE with VMPodFitRules, compiled as the
// apiserver compiles the stored policy. A workload's pod template is judged as a pod.
// It writes one tab-separated row per refusal: the object as Kind namespace/name, the
// rule id, the message. It makes no cluster call.
//
// It returns ErrVMPodFitRefused when a row was written, and another error for input
// that does not parse or a policy that does not compile.
func AuditVMPodFit(in io.Reader, out io.Writer) error {
	raw, err := io.ReadAll(in)
	if err != nil {
		return fmt.Errorf("vm pod fit audit: read input: %w", err)
	}
	var list struct {
		Kind  string            `json:"kind"`
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return fmt.Errorf("vm pod fit audit: parse input: %w", err)
	}
	items := list.Items
	switch {
	case list.Kind == "":
		return errors.New("vm pod fit audit: parse input: no kind; expected the output of kubectl get -o json")
	case !strings.HasSuffix(list.Kind, "List"):
		items = []json.RawMessage{raw}
	}

	c, err := compileVMPodFitAudit()
	if err != nil {
		return err
	}
	refused := false
	for i, item := range items {
		kind, meta, spec, err := vmAuditPodSpec(item)
		if err != nil {
			return fmt.Errorf("vm pod fit audit: item %d: %w", i, err)
		}
		if spec == nil {
			continue
		}
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: meta.Name, Namespace: meta.Namespace}, Spec: *spec}
		rows, err := c.judge(pod)
		if err != nil {
			rows = []vmAuditRow{{rule: "error", message: err.Error()}}
		}
		for _, r := range rows {
			refused = true
			if _, err := fmt.Fprintf(out, "%s %s/%s\t%s\t%s\n", kind, meta.Namespace, meta.Name, r.rule, r.message); err != nil {
				return fmt.Errorf("vm pod fit audit: write report: %w", err)
			}
		}
	}
	if refused {
		return ErrVMPodFitRefused
	}
	return nil
}

// vmAuditPodSpec decodes one item and returns its kind, metadata and the pod spec to
// judge: nil for a kind with no pod, or whose spec does not name the vm RuntimeClass.
func vmAuditPodSpec(item json.RawMessage) (string, metav1.ObjectMeta, *corev1.PodSpec, error) {
	var head struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(item, &head); err != nil {
		return "", metav1.ObjectMeta{}, nil, err
	}
	var (
		meta metav1.ObjectMeta
		spec corev1.PodSpec
		err  error
	)
	switch head.Kind {
	case "Pod":
		var o corev1.Pod
		err = json.Unmarshal(item, &o)
		meta, spec = o.ObjectMeta, o.Spec
	case "Deployment":
		var o appsv1.Deployment
		err = json.Unmarshal(item, &o)
		meta, spec = o.ObjectMeta, o.Spec.Template.Spec
	case "StatefulSet":
		var o appsv1.StatefulSet
		err = json.Unmarshal(item, &o)
		meta, spec = o.ObjectMeta, o.Spec.Template.Spec
	case "DaemonSet":
		var o appsv1.DaemonSet
		err = json.Unmarshal(item, &o)
		meta, spec = o.ObjectMeta, o.Spec.Template.Spec
	case "ReplicaSet":
		var o appsv1.ReplicaSet
		err = json.Unmarshal(item, &o)
		meta, spec = o.ObjectMeta, o.Spec.Template.Spec
	case "Job":
		var o batchv1.Job
		err = json.Unmarshal(item, &o)
		meta, spec = o.ObjectMeta, o.Spec.Template.Spec
	case "CronJob":
		var o batchv1.CronJob
		err = json.Unmarshal(item, &o)
		meta, spec = o.ObjectMeta, o.Spec.JobTemplate.Spec.Template.Spec
	case "":
		return "", meta, nil, errors.New("no kind")
	default:
		return head.Kind, meta, nil, nil
	}
	if err != nil {
		return head.Kind, meta, nil, fmt.Errorf("%s: %w", head.Kind, err)
	}
	if spec.RuntimeClassName == nil || *spec.RuntimeClassName != string(runtimev1.HandlerVM) {
		return head.Kind, meta, nil, nil
	}
	return head.Kind, meta, &spec, nil
}

type vmAuditRow struct{ rule, message string }

type vmAuditExpr struct {
	expression string
	returns    []*cel.Type
}

func (e *vmAuditExpr) GetExpression() string    { return e.expression }
func (e *vmAuditExpr) ReturnTypes() []*cel.Type { return e.returns }

type vmAuditVariable struct {
	vmAuditExpr
	name string
}

func (v *vmAuditVariable) GetName() string { return v.name }

// vmAuditCompiled is the policy compiled the way the apiserver compiles a stored one:
// one composited compiler, the variables stored first, then the match conditions, the
// validations and the message expressions.
type vmAuditCompiled struct {
	matcher     matchconditions.Matcher
	validations plugincel.ConditionEvaluator
	messages    plugincel.ConditionEvaluator
	rules       []VMPodFitRule
	scheme      *runtime.Scheme
}

var (
	vmAuditPodGVK = schema.GroupVersionKind{Version: "v1", Kind: "Pod"}
	vmAuditPodGVR = schema.GroupVersionResource{Version: "v1", Resource: "pods"}
)

func compileVMPodFitAudit() (*vmAuditCompiled, error) {
	compiler, err := plugincel.NewCompositedCompiler(environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion()))
	if err != nil {
		return nil, fmt.Errorf("vm pod fit audit: compiler: %w", err)
	}
	withAuthz := plugincel.OptionalVariableDeclarations{HasAuthorizer: true}
	for _, v := range VMPodFitVariables() {
		variable := &vmAuditVariable{vmAuditExpr{v.Expression, []*cel.Type{cel.AnyType, cel.DynType}}, v.Name}
		if res := compiler.CompileAndStoreVariable(variable, withAuthz, environment.StoredExpressions); res.Error != nil {
			return nil, fmt.Errorf("vm pod fit audit: variable %s: %w", v.Name, res.Error)
		}
	}
	conds := VMPodFitMatchConditions()
	accessors := make([]plugincel.ExpressionAccessor, len(conds))
	for i := range conds {
		accessors[i] = (*matchconditions.MatchCondition)(&conds[i])
	}
	match := compiler.CompileCondition(accessors, withAuthz, environment.StoredExpressions)
	failFail := admissionregistrationv1.Fail
	c := &vmAuditCompiled{
		matcher: matchconditions.NewMatcher(match, &failFail, "policy", "validate", vmPodFitPolicyName),
		rules:   VMPodFitRules(),
		scheme:  runtime.NewScheme(),
	}
	if err := corev1.AddToScheme(c.scheme); err != nil {
		return nil, fmt.Errorf("vm pod fit audit: scheme: %w", err)
	}
	validations := make([]plugincel.ExpressionAccessor, len(c.rules))
	messages := make([]plugincel.ExpressionAccessor, len(c.rules))
	for i, r := range c.rules {
		validations[i] = &vmAuditExpr{r.Validation.Expression, []*cel.Type{cel.BoolType}}
		if r.Validation.MessageExpression != "" {
			messages[i] = &vmAuditExpr{r.Validation.MessageExpression, []*cel.Type{cel.StringType}}
		}
	}
	c.validations = compiler.CompileCondition(validations, withAuthz, environment.StoredExpressions)
	c.messages = compiler.CompileCondition(messages, plugincel.OptionalVariableDeclarations{}, environment.StoredExpressions)
	for _, ev := range []plugincel.ConditionEvaluator{match, c.validations, c.messages} {
		if errs := ev.CompilationErrors(); len(errs) > 0 {
			return nil, fmt.Errorf("vm pod fit audit: policy does not compile: %v", errs)
		}
	}
	return c, nil
}

// judge evaluates a Pod CREATE as the validating policy does: the matcher, the
// validations, every message expression on the budget that remains, then a message
// for each refusal. An error is what failurePolicy Fail turns into a refusal.
func (c *vmAuditCompiled) judge(pod *corev1.Pod) ([]vmAuditRow, error) {
	ctx := context.Background()
	attrs := admission.NewAttributesRecord(pod, nil, vmAuditPodGVK, pod.Namespace, pod.Name, vmAuditPodGVR,
		"", admission.Create, &metav1.CreateOptions{}, false, &user.DefaultInfo{Name: "audit"})
	versioned, err := admission.NewVersionedAttributes(attrs, vmAuditPodGVK, admission.NewObjectInterfacesFromScheme(c.scheme))
	if err != nil {
		return nil, fmt.Errorf("versioned attributes: %w", err)
	}
	if res := c.matcher.Match(ctx, versioned, nil, nil); res.Error != nil {
		return nil, fmt.Errorf("match conditions: %w", res.Error)
	} else if !res.Matches {
		return nil, nil
	}
	request := plugincel.CreateAdmissionRequest(versioned.Attributes, metav1.GroupVersionResource(vmAuditPodGVR), metav1.GroupVersionKind(vmAuditPodGVK))
	results, left, err := c.validations.ForInput(ctx, versioned, request, plugincel.OptionalVariableBindings{}, nil, celconfig.RuntimeCELCostBudget)
	if err != nil {
		return nil, fmt.Errorf("validations: %w", err)
	}
	messages, _, err := c.messages.ForInput(ctx, versioned, request, plugincel.OptionalVariableBindings{}, nil, left)
	if err != nil {
		return nil, fmt.Errorf("message expressions: %w", err)
	}
	var rows []vmAuditRow
	for i, r := range results {
		if r.Error != nil {
			return nil, r.Error
		}
		if r.EvalResult != celtypes.True {
			rows = append(rows, vmAuditRow{c.rules[i].ID, vmAuditMessage(messages[i], c.rules[i].Validation)})
		}
	}
	return rows, nil
}

// vmAuditMessage chooses a refusal's text as the validator does: the rendered
// message, unless it failed, is over the size cap or holds a line break; then the
// static one.
func vmAuditMessage(rendered plugincel.EvaluationResult, rule admissionregistrationv1.Validation) string {
	if rendered.Error == nil && rendered.EvalResult != nil {
		if text, ok := rendered.EvalResult.Value().(string); ok {
			text = strings.TrimSpace(text)
			if text != "" && len(text) <= celconfig.MaxEvaluatedMessageExpressionSizeBytes && !strings.Contains(text, "\n") {
				return text
			}
		}
	}
	return rule.Message
}
