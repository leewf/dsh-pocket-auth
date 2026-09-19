import { mkdir, open, readFile, rename, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'

const FILE_NAME = 'totp-secret.json'

export async function openStore(directory) {
  await mkdir(directory, { recursive: true, mode: 0o700 })
  const file = join(directory, FILE_NAME)
  let record = null
  try {
    record = JSON.parse(await readFile(file, 'utf8'))
    validateRecord(record)
  } catch (error) {
    if (error?.code !== 'ENOENT') throw new Error('credential store is invalid', { cause: error })
  }
  return {
    file,
    read: () => record,
    async commit(next) {
      validateRecord(next)
      const temp = `${file}.tmp.${process.pid}`
      await writeFile(temp, `${JSON.stringify(next, null, 2)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' })
      try {
        await rename(temp, file)
        record = structuredClone(next)
      } catch (error) {
        await rm(temp, { force: true }).catch(() => {})
        throw error
      }
    },
  }
}

function validateRecord(record) {
  if (record === null || typeof record !== 'object' || Array.isArray(record)) throw new TypeError('credential record must be an object')
  if (record.schemaVersion !== 1 || !Number.isInteger(record.credentialVersion) || record.credentialVersion < 1) throw new TypeError('credential record schema mismatch')
  if (typeof record.secret !== 'string' || record.secret.length === 0) throw new TypeError('credential secret is missing')
  if (typeof record.lastAcceptedStep !== 'string' || !/^\d+$/.test(record.lastAcceptedStep)) throw new TypeError('lastAcceptedStep is invalid')
}
