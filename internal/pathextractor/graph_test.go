/**
 * Copyright 2026 Mia srl
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package pathextractor

import (
	"testing"

	"gotest.tools/assert"
)

func TestInsertPath(t *testing.T) {
	root := NewN("", false, 0)

	root.insertPath("/my/fantastic/path-with/:param1/params")

	assert.DeepEqual(t, &Node{
		Depth:   0,
		IsParam: false,
		Token:   "",
		Children: []*Node{{
			Token:   "my",
			Depth:   1,
			IsParam: false,
			Children: []*Node{{
				Token:   "fantastic",
				Depth:   2,
				IsParam: false,
				Children: []*Node{{
					Token:   "path-with",
					Depth:   3,
					IsParam: false,
					Children: []*Node{{
						Token:   ":param1",
						Depth:   4,
						IsParam: true,
						Children: []*Node{{
							Token:    "params",
							Depth:    5,
							IsParam:  false,
							Children: []*Node{},
						}},
					}},
				}},
			}},
		}},
	}, root)

	root.insertPath("/my/fantastic/path-with/:param2/params")
	assert.DeepEqual(t, &Node{
		Depth:   0,
		IsParam: false,
		Token:   "",
		Children: []*Node{{
			Token:   "my",
			Depth:   1,
			IsParam: false,
			Children: []*Node{{
				Token:   "fantastic",
				Depth:   2,
				IsParam: false,
				Children: []*Node{{
					Token:   "path-with",
					Depth:   3,
					IsParam: false,
					Children: []*Node{{
						Token:   ":param1",
						Depth:   4,
						IsParam: true,
						Children: []*Node{{
							Token:    "params",
							Depth:    5,
							IsParam:  false,
							Children: []*Node{},
						}},
					}, {
						Token:   ":param2",
						Depth:   4,
						IsParam: true,
						Children: []*Node{{
							Token:    "params",
							Depth:    5,
							IsParam:  false,
							Children: []*Node{},
						}},
					}},
				}},
			}},
		}},
	}, root)

	root.insertPath("/my/fantastic/path-with/:param2/params")
	assert.DeepEqual(t, &Node{
		Depth:   0,
		IsParam: false,
		Token:   "",
		Children: []*Node{{
			Token:   "my",
			Depth:   1,
			IsParam: false,
			Children: []*Node{{
				Token:   "fantastic",
				Depth:   2,
				IsParam: false,
				Children: []*Node{{
					Token:   "path-with",
					Depth:   3,
					IsParam: false,
					Children: []*Node{{
						Token:   ":param1",
						Depth:   4,
						IsParam: true,
						Children: []*Node{{
							Token:    "params",
							Depth:    5,
							IsParam:  false,
							Children: []*Node{},
						}},
					}, {
						Token:   ":param2",
						Depth:   4,
						IsParam: true,
						Children: []*Node{{
							Token:    "params",
							Depth:    5,
							IsParam:  false,
							Children: []*Node{},
						}},
					}},
				}},
			}},
		}},
	}, root)

	root.insertPath("/my/test")
	assert.DeepEqual(t, &Node{
		Depth:   0,
		IsParam: false,
		Token:   "",
		Children: []*Node{{
			Token:   "my",
			Depth:   1,
			IsParam: false,
			Children: []*Node{{
				Token:   "fantastic",
				Depth:   2,
				IsParam: false,
				Children: []*Node{{
					Token:   "path-with",
					Depth:   3,
					IsParam: false,
					Children: []*Node{{
						Token:   ":param1",
						Depth:   4,
						IsParam: true,
						Children: []*Node{{
							Token:    "params",
							Depth:    5,
							IsParam:  false,
							Children: []*Node{},
						}},
					}, {
						Token:   ":param2",
						Depth:   4,
						IsParam: true,
						Children: []*Node{{
							Token:    "params",
							Depth:    5,
							IsParam:  false,
							Children: []*Node{},
						}},
					}},
				}},
			}, {
				Token:    "test",
				Depth:    2,
				IsParam:  false,
				Children: []*Node{},
			}},
		}},
	}, root)

	root.insertPath("/my/test")
	assert.DeepEqual(t, &Node{
		Depth:   0,
		IsParam: false,
		Token:   "",
		Children: []*Node{{
			Token:   "my",
			Depth:   1,
			IsParam: false,
			Children: []*Node{{
				Token:   "fantastic",
				Depth:   2,
				IsParam: false,
				Children: []*Node{{
					Token:   "path-with",
					Depth:   3,
					IsParam: false,
					Children: []*Node{{
						Token:   ":param1",
						Depth:   4,
						IsParam: true,
						Children: []*Node{{
							Token:    "params",
							Depth:    5,
							IsParam:  false,
							Children: []*Node{},
						}},
					}, {
						Token:   ":param2",
						Depth:   4,
						IsParam: true,
						Children: []*Node{{
							Token:    "params",
							Depth:    5,
							IsParam:  false,
							Children: []*Node{},
						}},
					}},
				}},
			}, {
				Token:    "test",
				Depth:    2,
				IsParam:  false,
				Children: []*Node{},
			}},
		}},
	}, root)
}

func TestCreateBasePathExtractorGraph(t *testing.T) {
	prefixes := []string{
		"/the-base-path",
		"/extensions/:",
		"/extensions/:/something-else-that-is-prefix",
		"/extensions/something-else-again",
		"/pippo/something-else-that-is-prefix",
	}

	expected := &Node{
		Token: "",
		Depth: 0,
		Children: []*Node{{
			Depth:    1,
			Token:    "the-base-path",
			Children: []*Node{},
		}, {
			Token: "extensions",
			Depth: 1,
			Children: []*Node{{
				Token:   ":",
				IsParam: true,
				Depth:   2,
				Children: []*Node{{
					Depth:    3,
					Token:    "something-else-that-is-prefix",
					Children: []*Node{},
				}},
			}, {
				Depth:    2,
				Token:    "something-else-again",
				Children: []*Node{},
			}},
		}, {
			Depth: 1,
			Token: "pippo",
			Children: []*Node{{
				Depth:    2,
				Token:    "something-else-that-is-prefix",
				Children: []*Node{},
			}},
		}},
	}

	result := CreateBasePathExtractorGraph(prefixes)

	assert.DeepEqual(t, expected, result)
}
