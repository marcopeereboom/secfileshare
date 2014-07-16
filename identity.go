/*
 * Copyright (c) 2014 Marco Peereboom <marco@peereboom.us>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/marcopeereboom/mcrypt"
)

const (
	homeDir          = "/.secfileshare"
	identityFilename = "/secfileshare.id"
)

func identityExists() bool {
	_, err := os.Stat(dir + identityFilename)
	if err != nil {
		return false
	}
	return true
}

func identityOpen() error {
	s, err := ioutil.ReadFile(dir + identityFilename)
	if err != nil {
		return err
	}
	identity, err = mcrypt.UnmarshalIdentity(s)
	if err != nil {
		return err
	}

	return nil
}

func identitySave() error {
	f, err := os.OpenFile(dir+identityFilename,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0400)
	if err != nil {
		return err
	}
	defer f.Close()

	j, err := identity.Marshal()
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(f, "%s\n", j)
	if err != nil {
		return err
	}

	return nil
}
