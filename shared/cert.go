/*
 * Copyright (c) 2014 Conformal Systems LLC. <support@conformal.com>
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
	_ "crypto/sha512"

	"io/ioutil"

	"time"

	"github.com/conformal/btcutil"
)

func GenerateCert(certFilename, keyFilename string) error {
	cert, key, err := btcutil.NewTLSCertPair("auto",
		time.Now().Add(time.Duration(time.Hour*24*365*10)),
		[]string{})
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(certFilename, cert, 0400)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(keyFilename, key, 0400)
	if err != nil {
		return err
	}
	return nil
}
