import { mkdir, readFile, rename, writeFile } from "node:fs/promises"
import { dirname } from "node:path"

export class JsonStore {
  #filePath
  #state = Object.create(null)
  #writeQueue = Promise.resolve()

  constructor(filePath) {
    this.#filePath = filePath
  }

  async load() {
    try {
      const contents = await readFile(this.#filePath, "utf8")
      const parsed = JSON.parse(contents)
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("State file must contain a JSON object")
      }
      this.#state = parsed
    } catch (error) {
      if (error?.code !== "ENOENT") throw error
    }
  }

  get(namespace, key) {
    return this.#state[namespace]?.[key]
  }

  list(namespace) {
    return Object.keys(this.#state[namespace] ?? {}).sort()
  }

  async set(namespace, key, value) {
    const nextNamespace = { ...(this.#state[namespace] ?? {}), [key]: value }
    this.#state = { ...this.#state, [namespace]: nextNamespace }
    await this.#persist()
  }

  async delete(namespace, key) {
    if (!(key in (this.#state[namespace] ?? {}))) return false

    const nextNamespace = { ...this.#state[namespace] }
    delete nextNamespace[key]
    this.#state = { ...this.#state, [namespace]: nextNamespace }
    await this.#persist()
    return true
  }

  #persist() {
    this.#writeQueue = this.#writeQueue.then(async () => {
      await mkdir(dirname(this.#filePath), { recursive: true })
      const temporaryPath = `${this.#filePath}.${process.pid}.tmp`
      await writeFile(temporaryPath, JSON.stringify(this.#state), { mode: 0o600 })
      await rename(temporaryPath, this.#filePath)
    })
    return this.#writeQueue
  }
}
