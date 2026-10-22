// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package html

import (
	"strings"
	"unicode"
)

func parseDoctypeWithGuard(s string, guard *resourceGuard) (n *Node, quirks bool) {
	n = newResourceNode(guard, Node{Type: DoctypeNode})

	// Find the name.
	space := indexAnyWithGuard(s, whitespace, guard)
	if space == -1 {
		space = len(s)
	}
	n.Data = s[:space]
	// The comparison to "html" is case-sensitive.
	if n.Data != "html" {
		quirks = true
	}
	n.Data = mapStringWithGuard(n.Data, unicode.ToLower, guard)
	s = trimLeftWithGuard(s[space:], whitespace, guard)

	if len(s) < 6 {
		// It can't start with "PUBLIC" or "SYSTEM".
		// Ignore the rest of the string.
		return n, quirks || s != ""
	}

	key := mapStringWithGuard(s[:6], unicode.ToLower, guard)
	s = s[6:]
	for key == "public" || key == "system" {
		s = trimLeftWithGuard(s, whitespace, guard)
		if s == "" {
			break
		}
		quote := s[0]
		if quote != '"' && quote != '\'' {
			break
		}
		s = s[1:]
		q := indexAnyWithGuard(s, string(quote), guard)
		var id string
		if q == -1 {
			id = s
			s = ""
		} else {
			id = s[:q]
			s = s[q+1:]
		}
		n.Attr = append(growResourceSlice(n.Attr, 1, guard), Attribute{Key: key, Val: id})
		if key == "public" {
			key = "system"
		} else {
			key = ""
		}
	}

	if key != "" || s != "" {
		quirks = true
	} else if len(n.Attr) > 0 {
		if n.Attr[0].Key == "public" {
			public := mapStringWithGuard(n.Attr[0].Val, unicode.ToLower, guard)
			switch public {
			case "-//w3o//dtd w3 html strict 3.0//en//", "-/w3d/dtd html 4.0 transitional/en", "html":
				quirks = true
			default:
				for _, q := range quirkyIDs {
					if strings.HasPrefix(public, q) {
						quirks = true
						break
					}
				}
			}
			// The following two public IDs only cause quirks mode if there is no system ID.
			if len(n.Attr) == 1 && (strings.HasPrefix(public, "-//w3c//dtd html 4.01 frameset//") ||
				strings.HasPrefix(public, "-//w3c//dtd html 4.01 transitional//")) {
				quirks = true
			}
		}
		if lastAttr := n.Attr[len(n.Attr)-1]; lastAttr.Key == "system" &&
			strings.EqualFold(lastAttr.Val, "http://www.ibm.com/data/dtd/v11/ibmxhtml1-transitional.dtd") {
			quirks = true
		}
	}

	return n, quirks
}

// quirkyIDs is a list of public doctype identifiers that cause a document
// to be interpreted in quirks mode. The identifiers should be in lower case.
var quirkyIDs = []string{
	"+//silmaril//dtd html pro v0r11 19970101//",
	"-//advasoft ltd//dtd html 3.0 aswedit + extensions//",
	"-//as//dtd html 3.0 aswedit + extensions//",
	"-//ietf//dtd html 2.0 level 1//",
	"-//ietf//dtd html 2.0 level 2//",
	"-//ietf//dtd html 2.0 strict level 1//",
	"-//ietf//dtd html 2.0 strict level 2//",
	"-//ietf//dtd html 2.0 strict//",
	"-//ietf//dtd html 2.0//",
	"-//ietf//dtd html 2.1e//",
	"-//ietf//dtd html 3.0//",
	"-//ietf//dtd html 3.2 final//",
	"-//ietf//dtd html 3.2//",
	"-//ietf//dtd html 3//",
	"-//ietf//dtd html level 0//",
	"-//ietf//dtd html level 1//",
	"-//ietf//dtd html level 2//",
	"-//ietf//dtd html level 3//",
	"-//ietf//dtd html strict level 0//",
	"-//ietf//dtd html strict level 1//",
	"-//ietf//dtd html strict level 2//",
	"-//ietf//dtd html strict level 3//",
	"-//ietf//dtd html strict//",
	"-//ietf//dtd html//",
	"-//metrius//dtd metrius presentational//",
	"-//microsoft//dtd internet explorer 2.0 html strict//",
	"-//microsoft//dtd internet explorer 2.0 html//",
	"-//microsoft//dtd internet explorer 2.0 tables//",
	"-//microsoft//dtd internet explorer 3.0 html strict//",
	"-//microsoft//dtd internet explorer 3.0 html//",
	"-//microsoft//dtd internet explorer 3.0 tables//",
	"-//netscape comm. corp.//dtd html//",
	"-//netscape comm. corp.//dtd strict html//",
	"-//o'reilly and associates//dtd html 2.0//",
	"-//o'reilly and associates//dtd html extended 1.0//",
	"-//o'reilly and associates//dtd html extended relaxed 1.0//",
	"-//softquad software//dtd hotmetal pro 6.0::19990601::extensions to html 4.0//",
	"-//softquad//dtd hotmetal pro 4.0::19971010::extensions to html 4.0//",
	"-//spyglass//dtd html 2.0 extended//",
	"-//sq//dtd html 2.0 hotmetal + extensions//",
	"-//sun microsystems corp.//dtd hotjava html//",
	"-//sun microsystems corp.//dtd hotjava strict html//",
	"-//w3c//dtd html 3 1995-03-24//",
	"-//w3c//dtd html 3.2 draft//",
	"-//w3c//dtd html 3.2 final//",
	"-//w3c//dtd html 3.2//",
	"-//w3c//dtd html 3.2s draft//",
	"-//w3c//dtd html 4.0 frameset//",
	"-//w3c//dtd html 4.0 transitional//",
	"-//w3c//dtd html experimental 19960712//",
	"-//w3c//dtd html experimental 970421//",
	"-//w3c//dtd w3 html//",
	"-//w3o//dtd w3 html 3.0//",
	"-//webtechs//dtd mozilla html 2.0//",
	"-//webtechs//dtd mozilla html//",
}
