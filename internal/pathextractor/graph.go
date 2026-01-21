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

import "strings"

type Node struct {
	Token    string
	IsParam  bool
	Depth    int
	Children []*Node
}

func NewN(token string, isParam bool, depth int) *Node {
	return &Node{
		Token:    token,
		IsParam:  isParam,
		Depth:    depth,
		Children: make([]*Node, 0),
	}
}

func (n *Node) appendNewChild(token string, isParam bool, depth int) *Node {
	for _, child := range n.Children {
		if child.Token == token && child.IsParam == isParam {
			return child
		}
	}
	newNode := NewN(token, isParam, depth)
	n.Children = append(n.Children, newNode)
	return newNode
}

func (n *Node) insertPath(path string) {
	segments := strings.Split(strings.Trim(path, "/"), "/")

	current := n
	for depth, segment := range segments {
		isParam := strings.HasPrefix(segment, ":")
		current = current.appendNewChild(segment, isParam, depth+1)
	}
}

func CreateBasePathExtractorGraph(paths []string) *Node {
	root := NewN("", false, 0)
	for _, path := range paths {
		root.insertPath(path)
	}
	return root
}

func bfs(root *Node, path string) string {
	result := make([]string, 0)

	pathSegments := strings.Split(path, "/")

	queue := NewQ()
	queue.Push(root)
	for queue.Size() > 0 {
		cur := queue.Pop()
		pathToken := pathSegments[cur.Depth]
		if !cur.IsParam && cur.Token != pathToken {
			continue
		}

		result = append(result, pathToken)
		for _, c := range cur.Children {
			// TODO: prevent adding previously visited nodes!
			queue.Push(c)
		}
	}
	return strings.Join(result, "/")
}
