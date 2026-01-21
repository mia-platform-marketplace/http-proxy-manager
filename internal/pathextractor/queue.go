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
	"container/list"
)

type Queue struct {
	l *list.List
}

func NewQ() *Queue {
	return &Queue{
		l: list.New(),
	}
}

func (q *Queue) Push(n *Node) {
	q.l.PushBack(n)
}

func (q *Queue) Pop() *Node {
	frontNode := q.l.Front()
	node, ok := frontNode.Value.(*Node)
	if !ok {
		panic("ziobo")
	}
	q.l.Remove(frontNode)
	return node
}

func (q *Queue) Size() int {
	return q.l.Len()
}
