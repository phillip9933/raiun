package eu.opencloud.android.next.core.sync

/** Case-sensitive glob rules relative to a backup's selected source folder. */
class BackupExclusions private constructor(
    private val rules: List<Rule>,
) {
    /** Includes matches on ancestor directories so callers may check a file independently of traversal. */
    fun excludes(
        path: String,
        isDirectory: Boolean,
    ): Boolean {
        if (rules.isEmpty()) return false
        val parts = path.trim('/').split('/').filter(String::isNotEmpty)
        return parts.indices.any { index ->
            val directory = index < parts.lastIndex || isDirectory
            val relative = parts.take(index + 1).joinToString("/")
            rules.any { it.matches(relative, parts[index], directory) }
        }
    }

    private data class Rule(
        val tokens: List<String>,
        val basename: Boolean,
        val directoryOnly: Boolean,
    ) {
        fun matches(
            path: String,
            name: String,
            isDirectory: Boolean,
        ): Boolean = (!directoryOnly || isDirectory) && matchesGlob(tokens, if (basename) name else path)
    }

    companion object {
        /** Returns a message suitable for showing beside the editor field, or null when valid. */
        fun validate(patterns: String): String? =
            try {
                parse(patterns)
                null
            } catch (exception: IllegalArgumentException) {
                exception.message
            }

        fun parse(patterns: String): BackupExclusions {
            require(patterns.length <= 8192) { "Exclusion rules are too long (8,192 characters maximum)." }
            val lines = patterns.lines().filter(String::isNotBlank)
            require(lines.size <= 100) { "Use no more than 100 exclusion rules." }
            val rules =
                lines.mapIndexed { index, raw ->
                    val line = raw.removeSuffix("\r")
                    val number = index + 1
                    require(line.length <= 255) { "Rule $number is too long (255 characters maximum)." }
                    require(!line.startsWith('/')) { "Rule $number must be relative to the selected folder." }
                    require(
                        line.none { it == '\\' || it.isISOControl() },
                    ) { "Rule $number contains an invalid character." }
                    val body = line.removeSuffix("/")
                    require(body.isNotEmpty() && body.split('/').all { it.isNotEmpty() && it !in setOf(".", "..") }) {
                        "Rule $number has an invalid folder path."
                    }
                    Rule(tokenize(body), '/' !in body, line.endsWith('/'))
                }
            return BackupExclusions(rules)
        }

        private fun tokenize(glob: String): List<String> {
            val tokens = mutableListOf<String>()
            var index = 0
            while (index < glob.length) {
                val token =
                    when {
                        glob.startsWith("**/", index) -> "**/"
                        glob.startsWith("**", index) -> "**"
                        else -> glob[index].toString()
                    }
                tokens += token
                index += token.length
            }
            return tokens
        }

        private fun matchesGlob(
            tokens: List<String>,
            path: String,
        ): Boolean {
            var current = BooleanArray(path.length + 1).also { it[path.length] = true }
            for (token in tokens.asReversed()) {
                current =
                    when (token) {
                        "*", "**" -> matchStar(token, path, current)
                        "**/" -> matchGlobstarDirectory(path, current)
                        else -> matchCharacter(token, path, current)
                    }
            }
            return current[0]
        }

        private fun matchStar(
            token: String,
            path: String,
            suffix: BooleanArray,
        ): BooleanArray =
            BooleanArray(path.length + 1).also { result ->
                for (at in path.length downTo 0) {
                    result[at] =
                        suffix[at] ||
                        (at < path.length && (token == "**" || path[at] != '/') && result[at + 1])
                }
            }

        private fun matchGlobstarDirectory(
            path: String,
            suffix: BooleanArray,
        ): BooleanArray =
            BooleanArray(path.length + 1).also { result ->
                var slashCompletion = false
                for (at in path.length downTo 0) {
                    if (at < path.length && path[at] == '/' && suffix[at + 1]) {
                        slashCompletion = true
                    }
                    result[at] = suffix[at] || slashCompletion
                }
            }

        private fun matchCharacter(
            token: String,
            path: String,
            suffix: BooleanArray,
        ): BooleanArray =
            BooleanArray(path.length + 1).also { result ->
                for (at in path.indices) {
                    val matches = if (token == "?") path[at] != '/' else token[0] == path[at]
                    result[at] = matches && suffix[at + 1]
                }
            }
    }
}
