// SPDX-FileCopyrightText: 2022 Andre 'Staltz' Medeiros <contact@staltz.com>
//
// SPDX-License-Identifier: CC0-1.0

const test = require('tape')
const ssbKeys = require('ssb-keys')
const { check } = require('ssb-feed-format')

const format = require('../format')

test('passes ssb-feed-format', (t) => {
  check(
    format,
    () => ssbKeys.generate(null, 'alice', 'buttwoo-v1'),
    { tag: 0 },
    (err) => {
      t.error(err, 'no error')
      if (err) console.log(err)
      t.end()
    }
  )
})
