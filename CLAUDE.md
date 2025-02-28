# IMAP Filter Project Guidelines

## Commands
- Build: `cargo build` or `cargo build --release` for optimized version
- Run: `cargo run -- --config path/to/config.toml`
- Test all: `cargo test`
- Test single: `cargo test test_name` (e.g., `cargo test test_filter_message`)
- Check: `cargo check` (quick verification without building)

## Code Style
- Use `snake_case` for functions, variables, and modules
- Use `PascalCase` for structs, enums, and traits
- Use `SCREAMING_SNAKE_CASE` for constants
- Group imports by external/internal, alphabetical within groups
- Prefer `?` operator for error propagation
- Use Result<T, Box<dyn std::error::Error>> for function returns
- Include descriptive error messages with context
- Add documentation comments to public functions and types
- Keep functions small and focused on a single responsibility
- Use strong typing and avoid type aliases for clarity
- Implement traits for extensibility where appropriate
- Use TOML for configuration files
- Configuration options should have clear defaults and documentation