const test = require('ava')

const secs = require('../lib/help/ms')

const values = {
  sec: 1000,
  secs: 1000,
  second: 1000,
  seconds: 1000,
  s: 1000,
  minute: 60000,
  minutes: 60000,
  min: 60000,
  mins: 60000,
  m: 60000,
  hour: 3600000,
  hours: 3600000,
  hr: 3600000,
  hrs: 3600000,
  h: 3600000,
  day: 86400000,
  days: 86400000,
  d: 86400000,
  week: 604800000,
  weeks: 604800000,
  w: 604800000,
  year: 31557600000,
  years: 31557600000,
  yr: 31557600000,
  yrs: 31557600000,
  y: 31557600000
}

test('invalid formats', t => {
  ;['-1w', '2.2.w', '2.w', '2.', '', '2 w       ', '     2w'].forEach((val) => {
    t.throws(() => {
      secs(val)
    }, { instanceOf: TypeError })
  })
})

Object.entries(values).forEach(([unit, value]) => {
  test(`0 ${unit}`, t => {
    t.is(0, secs(`0 ${unit}`))
  })

  test(`1 ${unit}`, t => {
    t.is(value, secs(`1 ${unit}`))
  })

  test(`2${unit}`, t => {
    t.is(2 * value, secs(`2${unit}`))
  })

  test(`2.5${unit}`, t => {
    t.is(Math.round(2.5 * value), secs(`2.5${unit}`))
  })
})
