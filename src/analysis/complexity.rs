use std::path::Path;
use anyhow::Result;

use super::ComplexityMetrics;

pub struct ComplexityCalculator;

impl ComplexityCalculator {
    pub fn new() -> Self {
        Self
    }

    pub fn calculate_complexity_metrics(&self, lines: &[&str], file_path: &Path) -> Result<ComplexityMetrics> {
        let function_count = self.calculate_function_count(lines, file_path);
        let max_nesting = self.calculate_max_nesting(lines);
        let cyclomatic_complexity = self.calculate_cyclomatic_complexity(lines, file_path)?;
        let cognitive_complexity = self.calculate_cognitive_complexity(lines, file_path)?;

        let maintainability_index = self.calculate_maintainability_index(
            cyclomatic_complexity,
            lines.len(),
            function_count,
        );

        Ok(ComplexityMetrics {
            cyclomatic_complexity,
            cognitive_complexity,
            nesting_depth: max_nesting,
            function_count,
            line_count: lines.len(),
            maintainability_index,
        })
    }

    fn calculate_function_count(&self, lines: &[&str], file_path: &Path) -> usize {
        let extension = file_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        lines
            .iter()
            .filter(|line| {
                let line = line.trim();
                match extension {
                    "rs" => {
                        line.starts_with("fn ") || line.contains(" fn ") ||
                        line.starts_with("async fn ") || line.contains(" async fn ")
                    }
                    "py" => {
                        line.starts_with("def ") || line.starts_with("async def ")
                    }
                    "js" | "ts" | "jsx" | "tsx" => {
                        line.contains("function ") || line.contains("=> {") ||
                        line.contains("async function") || line.contains("function*")
                    }
                    "java" | "cs" => {
                        (line.contains(" void ") || line.contains(" int ") || line.contains(" string ") ||
                         line.contains(" bool ") || line.contains(" double ") || line.contains(" float ")) &&
                        line.contains("(") && !line.contains("=")
                    }
                    "cpp" | "c" | "h" | "hpp" | "cc" | "cxx" => {
                        (line.contains("(") && line.contains(")") && line.contains("{")) ||
                        (line.starts_with("static ") || line.starts_with("extern ") ||
                         line.contains(" main(") || line.contains("void ") || line.contains("int "))
                    }
                    "go" => {
                        line.starts_with("func ") || line.contains(" func ")
                    }
                    "rb" => {
                        line.starts_with("def ") || line.contains(" def ")
                    }
                    "php" => {
                        line.contains("function ") || line.starts_with("function ")
                    }
                    _ => {
                        line.contains("function ") || line.contains("def ") || line.contains("fn ")
                    }
                }
            })
            .count()
    }

    fn calculate_cyclomatic_complexity(&self, lines: &[&str], file_path: &Path) -> Result<f64> {
        let extension = file_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        let mut complexity = 1.0; // Base complexity

        for line in lines {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with("//") || line.starts_with('#')
                || line.starts_with("/*") || line.starts_with('*') {
                continue;
            }

            complexity += match extension {
                "rs" => self.calculate_rust_complexity(line),
                "py" => self.calculate_python_complexity(line),
                "js" | "ts" | "jsx" | "tsx" => self.calculate_javascript_complexity(line),
                "java" => self.calculate_java_complexity(line),
                "cpp" | "c" | "h" | "hpp" | "cc" | "cxx" => self.calculate_c_cpp_complexity(line),
                "go" => self.calculate_go_complexity(line),
                "rb" => self.calculate_ruby_complexity(line),
                "php" => self.calculate_php_complexity(line),
                "cs" => self.calculate_csharp_complexity(line),
                _ => self.calculate_generic_complexity(line),
            };
        }

        Ok(complexity)
    }

    fn calculate_rust_complexity(&self, line: &str) -> f64 {
        let mut complexity = 0.0;

        // Control flow
        if line.contains("if ") || line.contains("else if ") { complexity += 1.0; }
        if line.contains("match ") { complexity += 1.0; }
        if line.contains("for ") || line.contains("while ") || line.contains("loop ") { complexity += 1.0; }
        if line.contains("?") && !line.contains("\"") { complexity += 1.0; } // Error propagation
        if line.contains("&&") || line.contains("||") { complexity += 0.5; }

        // Pattern matching arms
        complexity += (line.matches("=>").count() as f64) * 0.5;

        complexity
    }

    fn calculate_python_complexity(&self, line: &str) -> f64 {
        let mut complexity = 0.0;

        // Control flow
        if line.starts_with("if ") || line.contains(" if ") { complexity += 1.0; }
        if line.starts_with("elif ") { complexity += 1.0; }
        if line.starts_with("for ") || line.starts_with("while ") { complexity += 1.0; }
        if line.starts_with("try:") || line.starts_with("except ") { complexity += 1.0; }
        if line.contains(" and ") || line.contains(" or ") { complexity += 0.5; }

        // List/dict comprehensions
        if line.contains(" for ") && (line.contains("[") || line.contains("{")) { complexity += 1.0; }

        complexity
    }

    fn calculate_javascript_complexity(&self, line: &str) -> f64 {
        let mut complexity = 0.0;

        // Control flow
        if line.contains("if (") || line.contains("if(") { complexity += 1.0; }
        if line.contains("else if") { complexity += 1.0; }
        if line.contains("for (") || line.contains("for(") { complexity += 1.0; }
        if line.contains("while (") || line.contains("while(") { complexity += 1.0; }
        if line.contains("switch ") { complexity += 1.0; }
        if line.contains("case ") { complexity += 0.5; }
        if line.contains("try {") || line.contains("catch (") { complexity += 1.0; }
        if line.contains("&&") || line.contains("||") { complexity += 0.5; }

        // Ternary operators
        complexity += (line.matches("?").count() as f64) * 0.5;

        complexity
    }

    fn calculate_java_complexity(&self, line: &str) -> f64 {
        let mut complexity = 0.0;

        // Control flow
        if line.contains("if (") || line.contains("if(") { complexity += 1.0; }
        if line.contains("else if") { complexity += 1.0; }
        if line.contains("for (") || line.contains("for(") { complexity += 1.0; }
        if line.contains("while (") || line.contains("while(") { complexity += 1.0; }
        if line.contains("switch (") { complexity += 1.0; }
        if line.contains("case ") { complexity += 0.5; }
        if line.contains("try {") || line.contains("catch (") { complexity += 1.0; }
        if line.contains("&&") || line.contains("||") { complexity += 0.5; }

        complexity
    }

    fn calculate_c_cpp_complexity(&self, line: &str) -> f64 {
        let mut complexity = 0.0;

        // Basic control flow
        if line.contains("if (") || line.contains("if(") { complexity += 1.0; }
        if line.contains("else if") { complexity += 1.0; }
        if line.contains("for (") || line.contains("for(") { complexity += 1.0; }
        if line.contains("while (") || line.contains("while(") { complexity += 1.0; }
        if line.contains("do {") || line.contains("do\n") { complexity += 1.0; }
        if line.contains("switch (") { complexity += 1.0; }
        if line.contains("case ") && line.contains(":") { complexity += 0.5; }

        // Logical operators
        if line.contains("&&") || line.contains("||") { complexity += 0.5; }

        // Ternary operators
        complexity += (line.matches("?").count() as f64) * 0.5;

        // Exception handling (C++)
        if line.contains("try {") || line.contains("catch (") || line.contains("throw ") {
            complexity += 1.0;
        }

        // Memory management patterns (high complexity/security risk)
        if line.contains("malloc(") || line.contains("calloc(") || line.contains("realloc(") {
            complexity += 1.5; // Memory allocation adds complexity
        }
        if line.contains("free(") { complexity += 1.0; }
        if line.contains("new ") || line.contains("delete ") { complexity += 1.0; }

        // Pointer arithmetic (security-relevant complexity)
        if line.contains("++") || line.contains("--") {
            if line.contains("*") { complexity += 1.5; } // Pointer increment/decrement
            else { complexity += 0.5; }
        }

        // Function pointers and callbacks
        if line.contains("(*") && line.contains(")(") { complexity += 2.0; }
        if line.contains("->") { complexity += 0.5; } // Member access through pointer

        // Preprocessor directives (can hide complexity)
        if line.trim().starts_with("#if") || line.trim().starts_with("#ifdef") ||
           line.trim().starts_with("#ifndef") { complexity += 1.0; }
        if line.trim().starts_with("#else") || line.trim().starts_with("#elif") {
            complexity += 0.5;
        }

        // Macros with parameters (can be very complex)
        if line.contains("#define") && line.contains("(") && line.contains(")") {
            complexity += 1.5;
        }

        // Assembly inline (high complexity)
        if line.contains("__asm") || line.contains("asm(") { complexity += 3.0; }

        // Goto statements (discouraged, high complexity)
        if line.contains("goto ") { complexity += 2.5; }

        // setjmp/longjmp (non-local jumps, very complex)
        if line.contains("setjmp(") || line.contains("longjmp(") { complexity += 3.0; }

        // Variadic functions
        if line.contains("va_start") || line.contains("va_arg") || line.contains("...") {
            complexity += 1.5;
        }

        // Buffer operations (security-critical)
        if line.contains("strcpy(") || line.contains("strcat(") || line.contains("sprintf(") ||
           line.contains("gets(") || line.contains("scanf(") { complexity += 2.0; }

        // Safer alternatives (still complex but better)
        if line.contains("strncpy(") || line.contains("strncat(") || line.contains("snprintf(") ||
           line.contains("fgets(") { complexity += 1.0; }

        // Thread synchronization (high complexity)
        if line.contains("pthread_") || line.contains("mutex") || line.contains("semaphore") {
            complexity += 2.0;
        }

        // Signal handling
        if line.contains("signal(") || line.contains("sigaction(") { complexity += 2.0; }

        // Type casting (can hide issues)
        if line.matches("(").count() >= 2 && (
            line.contains("int*") || line.contains("char*") || line.contains("void*") ||
            line.contains("**)") || line.contains("(*)")
        ) {
            complexity += 1.0;
        }

        complexity
    }

    fn calculate_go_complexity(&self, line: &str) -> f64 {
        let mut complexity = 0.0;

        // Control flow
        if line.contains("if ") { complexity += 1.0; }
        if line.contains("for ") { complexity += 1.0; }
        if line.contains("switch ") { complexity += 1.0; }
        if line.contains("case ") { complexity += 0.5; }
        if line.contains("select {") { complexity += 1.0; }
        if line.contains("&&") || line.contains("||") { complexity += 0.5; }

        // Error handling
        if line.contains("if err != nil") { complexity += 1.0; }

        complexity
    }

    fn calculate_ruby_complexity(&self, line: &str) -> f64 {
        let mut complexity = 0.0;

        // Control flow
        if line.starts_with("if ") || line.contains(" if ") { complexity += 1.0; }
        if line.starts_with("elsif ") { complexity += 1.0; }
        if line.starts_with("for ") || line.starts_with("while ") { complexity += 1.0; }
        if line.starts_with("case ") || line.starts_with("when ") { complexity += 0.5; }
        if line.contains(" and ") || line.contains(" or ") { complexity += 0.5; }

        // Blocks
        if line.contains(" do ") || line.contains(" { ") { complexity += 0.5; }

        complexity
    }

    fn calculate_php_complexity(&self, line: &str) -> f64 {
        let mut complexity = 0.0;

        // Control flow
        if line.contains("if (") || line.contains("if(") { complexity += 1.0; }
        if line.contains("elseif ") { complexity += 1.0; }
        if line.contains("for (") || line.contains("foreach (") { complexity += 1.0; }
        if line.contains("while (") { complexity += 1.0; }
        if line.contains("switch (") { complexity += 1.0; }
        if line.contains("case ") { complexity += 0.5; }
        if line.contains("try {") || line.contains("catch (") { complexity += 1.0; }
        if line.contains("&&") || line.contains("||") { complexity += 0.5; }

        complexity
    }

    fn calculate_csharp_complexity(&self, line: &str) -> f64 {
        let mut complexity = 0.0;

        // Control flow
        if line.contains("if (") || line.contains("if(") { complexity += 1.0; }
        if line.contains("else if") { complexity += 1.0; }
        if line.contains("for (") || line.contains("foreach (") { complexity += 1.0; }
        if line.contains("while (") { complexity += 1.0; }
        if line.contains("switch (") { complexity += 1.0; }
        if line.contains("case ") { complexity += 0.5; }
        if line.contains("try {") || line.contains("catch (") { complexity += 1.0; }
        if line.contains("&&") || line.contains("||") { complexity += 0.5; }

        // LINQ
        if line.contains(".Where(") || line.contains(".Select(") { complexity += 0.5; }

        complexity
    }

    fn calculate_generic_complexity(&self, line: &str) -> f64 {
        let mut complexity = 0.0;

        // Basic control flow keywords
        let keywords = ["if", "for", "while", "switch", "case", "catch"];
        for keyword in &keywords {
            complexity += (line.matches(keyword).count() as f64) * 0.5;
        }

        // Logical operators
        if line.contains("&&") || line.contains("||") { complexity += 0.5; }

        complexity
    }

    fn calculate_cognitive_complexity(&self, lines: &[&str], file_path: &Path) -> Result<f64> {
        let extension = file_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        let mut cognitive_complexity = 0.0;
        let mut nesting_level = 0;
        let mut in_switch = false;

        for line in lines {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with("//") || line.starts_with('#')
                || line.starts_with("/*") || line.starts_with('*') {
                continue;
            }

            // Track nesting level changes
            let _old_nesting = nesting_level;
            nesting_level += self.calculate_nesting_increment(line, extension);
            nesting_level = nesting_level.max(0);

            // Calculate cognitive complexity increment based on constructs
            let increment = self.calculate_cognitive_increment(line, extension, nesting_level, &mut in_switch);
            cognitive_complexity += increment;

            // Special handling for closing braces that reduce nesting
            if line.contains("}") || (extension == "py" && !line.starts_with(' ')) {
                nesting_level = (nesting_level - 1).max(0);
                if line.contains("}") && in_switch {
                    in_switch = false;
                }
            }
        }

        Ok(cognitive_complexity)
    }

    fn calculate_nesting_increment(&self, line: &str, extension: &str) -> i32 {
        let mut increment = 0;

        match extension {
            "py" => {
                // Python uses indentation
                let _indent_level = (line.len() - line.trim_start().len()) / 4;
                // This is simplified - proper implementation would track indentation changes
                if line.trim_start().starts_with("if ") ||
                   line.trim_start().starts_with("for ") ||
                   line.trim_start().starts_with("while ") ||
                   line.trim_start().starts_with("try:") ||
                   line.trim_start().starts_with("with ") {
                    increment += 1;
                }
            }
            _ => {
                // Brace-based languages
                if line.contains("{") { increment += 1; }
                if line.contains("}") { increment -= 1; }
            }
        }

        increment
    }

    fn calculate_cognitive_increment(&self, line: &str, extension: &str, nesting_level: i32, in_switch: &mut bool) -> f64 {
        let mut increment = 0.0;
        let nesting_penalty = nesting_level.max(0) as f64;

        // Control flow structures (base increment + nesting penalty)
        if line.contains("if ") && !line.contains("else if") {
            increment += 1.0 + nesting_penalty;
        } else if line.contains("else if") || line.contains("elif ") {
            increment += 1.0 + nesting_penalty;
        } else if line.contains("else") && !line.contains("if") {
            increment += 1.0 + nesting_penalty;
        }

        // Loops
        if line.contains("for ") || line.contains("while ") || line.contains("do ") {
            increment += 1.0 + nesting_penalty;
        }

        // Switch statements
        if line.contains("switch ") {
            increment += 1.0 + nesting_penalty;
            *in_switch = true;
        }

        // Case statements don't add extra complexity in cognitive complexity
        // (unlike cyclomatic complexity)

        // Exception handling
        if line.contains("try") || line.contains("catch") || line.contains("except") {
            increment += 1.0 + nesting_penalty;
        }

        // Language-specific patterns
        match extension {
            "rs" => {
                // Rust-specific patterns
                if line.contains("match ") {
                    increment += 1.0 + nesting_penalty;
                }
                if line.contains("?") && !line.contains("\"") {
                    increment += 1.0; // Error propagation adds cognitive load
                }
            }
            "js" | "ts" | "jsx" | "tsx" => {
                // JavaScript-specific patterns
                if line.contains(".then(") || line.contains(".catch(") {
                    increment += 1.0 + nesting_penalty;
                }
                if line.contains("async ") || line.contains("await ") {
                    increment += 1.0; // Async patterns add cognitive load
                }
            }
            "cpp" | "c" | "h" | "hpp" | "cc" | "cxx" => {
                // C/C++ specific patterns that add cognitive load
                if line.contains("goto ") {
                    increment += 3.0; // Goto jumps are very complex cognitively
                }
                if line.contains("setjmp") || line.contains("longjmp") {
                    increment += 4.0; // Non-local jumps are extremely complex
                }
                if line.contains("#if") || line.contains("#ifdef") {
                    increment += 1.0 + nesting_penalty; // Preprocessor conditionals
                }
                if line.contains("(*") && line.contains(")(") {
                    increment += 2.0; // Function pointers are cognitively complex
                }
            }
            _ => {}
        }

        // Logical operators (but not as much penalty as control flow)
        if line.contains("&&") || line.contains("||") {
            increment += 0.5;
        }

        // Ternary operators
        increment += (line.matches("?").count() as f64) * 0.5;

        increment
    }

    fn calculate_max_nesting(&self, lines: &[&str]) -> usize {
        let mut max_nesting = 0;
        let mut current_nesting: usize = 0;

        for line in lines {
            let trimmed = line.trim();

            // Count opening braces/keywords that increase nesting
            if trimmed.ends_with('{')
                || trimmed.starts_with("if ")
                || trimmed.starts_with("for ")
                || trimmed.starts_with("while ")
            {
                current_nesting += 1;
                max_nesting = max_nesting.max(current_nesting);
            }

            // Count closing braces that decrease nesting
            if trimmed == "}" || trimmed.starts_with("}") {
                current_nesting = current_nesting.saturating_sub(1);
            }
        }

        max_nesting
    }

    fn calculate_maintainability_index(
        &self,
        complexity: f64,
        lines: usize,
        _functions: usize,
    ) -> f64 {
        let halstead_volume = (lines as f64).ln() * 4.0;

        let maintainability =
            171.0 - 5.2 * halstead_volume.ln() - 0.23 * complexity - 16.2 * (lines as f64).ln();

        maintainability.max(0.0).min(100.0)
    }
}
