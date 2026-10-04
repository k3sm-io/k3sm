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

// Package defaults holds the few constant values shared by the installer and
// the runtime packages (provider, netserve, dev). Admission rule: a value
// belongs here only if more than one of those sides needs it, it imports
// nothing beyond the standard library, and nothing about it is private to the
// installer. It exists so a runtime package never has to import pkg/install,
// and with it the whole privileged-orchestration surface, for a string.
package defaults
