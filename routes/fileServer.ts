/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'

export function servePublicFiles () {
  return ({ params, query }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (!file.includes('/')) {
      verify(file, res, next)
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }

  function verify (file: string, res: Response, next: NextFunction) {
    const sanitizedFile = security.cutOffPoisonNullByte(file)
    const ftpDirectory = path.resolve('ftp')
    const requestedFile = path.resolve(ftpDirectory, sanitizedFile)

    const isSafeFileName =
      sanitizedFile === path.basename(sanitizedFile) &&
      !sanitizedFile.includes('..') &&
      !sanitizedFile.includes('/') &&
      !sanitizedFile.includes('\\') &&
      !sanitizedFile.includes('\0')

    const isInsideFtpDirectory =
      requestedFile.startsWith(ftpDirectory + path.sep)

    const hasAllowedType =
      endsWithAllowlistedFileType(sanitizedFile) ||
      sanitizedFile === 'incident-support.kdbx'

    if (!isSafeFileName || !isInsideFtpDirectory || !hasAllowedType) {
      res.status(403)
      next(new Error('Invalid or unauthorized file name.'))
      return
    }

    challengeUtils.solveIf(challenges.directoryListingChallenge, () => {
      return sanitizedFile.toLowerCase() === 'acquisitions.md'
    })

    res.sendFile(requestedFile)
  }

  function endsWithAllowlistedFileType (param: string) {
    return param.endsWith('.md') || param.endsWith('.pdf')
  }
}
