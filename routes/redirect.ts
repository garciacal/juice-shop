/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'

export function performRedirect () {
  return ({ query }: Request, res: Response, next: NextFunction) => {
    if (typeof query.to !== 'string' || query.to.length > 2048) {
      res.status(400)
      next(new Error('Invalid redirect target.'))
      return
    }

    const toUrl = query.to

    try {
      const parsedUrl = new URL(toUrl)

      if (parsedUrl.protocol !== 'https:') {
        res.status(406)
        next(new Error('Only HTTPS redirect targets are allowed.'))
        return
      }

      const normalizedTarget = parsedUrl.toString()
      const isAllowed = Array.from(security.redirectAllowlist).some((allowedUrl: string) => {
        try {
          return new URL(allowedUrl).toString() === normalizedTarget
        } catch {
          return false
        }
      })

      if (!isAllowed) {
        res.status(406)
        next(new Error('Unrecognized target URL for redirect.'))
        return
      }

      challengeUtils.solveIf(challenges.redirectCryptoCurrencyChallenge, () => {
        return toUrl === 'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW' ||
          toUrl === 'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm' ||
          toUrl === 'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6'
      })

      res.redirect(normalizedTarget)
    } catch {
      res.status(400)
      next(new Error('Malformed redirect target.'))
    }
  }
}
