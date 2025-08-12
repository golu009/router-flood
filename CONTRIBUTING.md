# Contributing to Router Flood

Thank you for your interest in contributing to Router Flood! This document provides guidelines and information for contributors to help maintain code quality and project consistency.

## 🚨 Important Ethical Guidelines

**Before contributing, please understand:**

- This tool is **strictly for educational and authorized testing purposes only**
- Contributions must not facilitate malicious use or bypass safety mechanisms
- All features must include appropriate safety validations and limits
- Documentation must emphasize ethical usage and legal compliance

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Code Style](#code-style)
- [Pull Request Process](#pull-request-process)
- [Issue Reporting](#issue-reporting)
- [Architecture Guidelines](#architecture-guidelines)

## 📜 Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inspiring community for all. We pledge to make participation in our project a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, gender identity and expression, level of experience, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Expected Behavior

- **Ethical Usage**: Promote responsible and authorized network testing only
- **Respectful Communication**: Use welcoming and inclusive language
- **Constructive Feedback**: Focus on what is best for the community
- **Safety First**: Always consider security implications of contributions
- **Documentation**: Help others understand your contributions

### Unacceptable Behavior

- **Malicious Features**: Contributing code intended to bypass safety mechanisms
- **Harassment**: Trolling, insulting/derogatory comments, personal attacks
- **Unauthorized Testing**: Promoting use against non-authorized targets
- **Security Vulnerabilities**: Intentionally introducing security flaws

## 🚀 Getting Started

### Prerequisites

- **Rust**: Version 1.70+ with Cargo
- **Git**: For version control
- **Development Environment**: Linux preferred, macOS supported
- **Network Knowledge**: Understanding of network protocols and ethical testing

### Initial Setup

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/router-flood.git
   cd router-flood
   ```
3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/paulshpilsher/router-flood.git
   ```
4. **Create a branch** for your feature:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## 🛠️ Development Setup

### Build and Test

```bash
# Build the project
cargo build

# Run all tests
cargo test

# Run with detailed output
cargo test -- --nocapture

# Check code formatting
cargo fmt --check

# Run linter
cargo clippy -- -D warnings
```

### Development Tools

```bash
# Install additional tools
cargo install cargo-audit
cargo install cargo-outdated

# Security audit
cargo audit

# Check for outdated dependencies
cargo outdated
```

### Environment Setup

```bash
# Enable debug logging
export RUST_LOG=debug

# Run in dry-run mode for safe testing
cargo run -- --target 192.168.1.1 --ports 80 --dry-run
```

## 🔄 Making Changes

### Branch Naming

Use descriptive branch names with prefixes:

- `feature/` - New features
- `fix/` - Bug fixes  
- `docs/` - Documentation updates
- `test/` - Test improvements
- `refactor/` - Code refactoring

Examples:
- `feature/add-ipv6-support`
- `fix/config-parsing-error`
- `docs/update-yaml-examples`

### Commit Messages

Follow conventional commit format:

```
type(scope): brief description

Detailed explanation if needed.

- Include any breaking changes
- Reference issues: Fixes #123
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `test`: Tests
- `refactor`: Code refactoring
- `style`: Code formatting
- `security`: Security improvements

**Examples:**
```
feat(packet): add IPv6 UDP packet generation

Add support for IPv6 UDP packets with proper header construction
and validation. Includes comprehensive tests for all IPv6 scenarios.

- Extends PacketBuilder with IPv6 capabilities
- Maintains safety validation for IPv6 addresses
- Fixes #45
```

## 🧪 Testing

### Test Requirements

**All contributions must include tests:**

- **Unit Tests**: For individual functions and methods
- **Integration Tests**: For module interactions  
- **Error Handling**: For failure scenarios
- **Safety Validation**: For security features

### Test Structure

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_your_feature() {
        // Arrange
        let input = setup_test_data();
        
        // Act  
        let result = your_function(input);
        
        // Assert
        assert_eq!(result, expected_value);
    }
    
    #[tokio::test]
    async fn test_async_feature() {
        // Test async functionality
    }
}
```

### Running Tests

```bash
# Run all tests
cargo test

# Run specific test module
cargo test config_tests

# Run with coverage (requires cargo-tarpaulin)
cargo tarpaulin --out Html

# Run tests with memory sanitizer
RUSTFLAGS="-Z sanitizer=address" cargo test
```

### Test Guidelines

- **Descriptive Names**: Test names should clearly describe what is being tested
- **Independent Tests**: Each test should be isolated and not depend on others
- **Edge Cases**: Include tests for boundary conditions and error cases
- **Safety Features**: Always test security validations and safety limits
- **Mock External Dependencies**: Use mocks for network interfaces, file systems, etc.

## 🎨 Code Style

### Rust Style Guidelines

We follow standard Rust conventions:

```rust
// Use descriptive variable names
let packet_builder = PacketBuilder::new(size_range, protocol_mix);

// Prefer early returns for error conditions
fn validate_ip(ip: &str) -> Result<()> {
    if ip.is_empty() {
        return Err(ValidationError::EmptyInput);
    }
    
    // Continue with validation logic
    Ok(())
}

// Use proper error handling
match result {
    Ok(value) => process_value(value),
    Err(e) => {
        tracing::error!("Operation failed: {}", e);
        return Err(e.into());
    }
}
```

### Documentation

```rust
/// Brief description of the function
///
/// More detailed explanation if needed, including:
/// - Parameter descriptions
/// - Return value explanation  
/// - Error conditions
/// - Usage examples
///
/// # Arguments
///
/// * `target` - The target IP address (must be private range)
/// * `port` - The target port number
///
/// # Returns
///
/// Returns `Ok(())` on success, or an error if validation fails
///
/// # Examples
///
/// ```rust
/// let result = validate_target("192.168.1.1", 80);
/// assert!(result.is_ok());
/// ```
///
/// # Safety
///
/// This function validates that the target IP is in a private range
/// to prevent unauthorized network testing.
pub fn validate_target(target: &str, port: u16) -> Result<()> {
    // Implementation
}
```

### Formatting

```bash
# Format code before committing
cargo fmt

# Check formatting without making changes  
cargo fmt --check
```

## 🔍 Pull Request Process

### Before Submitting

1. **Run all tests**: `cargo test`
2. **Format code**: `cargo fmt`  
3. **Run linter**: `cargo clippy`
4. **Update documentation**: Including README if needed
5. **Add tests**: For all new functionality
6. **Security review**: Ensure no safety mechanisms are bypassed

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature  
- [ ] Documentation update
- [ ] Refactoring
- [ ] Security improvement

## Testing
- [ ] All existing tests pass
- [ ] New tests added for new functionality
- [ ] Manual testing completed

## Safety Checklist
- [ ] No bypass of IP range validation
- [ ] Rate limiting maintained
- [ ] Audit logging preserved
- [ ] Documentation updated with safety notes

## Breaking Changes
List any breaking changes

## Issues
Fixes #(issue number)
```

### Review Process

1. **Automated Checks**: GitHub Actions CI/CD pipeline runs comprehensive validation:
   - **Build Verification**: `cargo build --verbose` ensures compilation success
   - **Test Execution**: `cargo test --verbose` runs all 140 tests
   - **Quality Gates**: All tests must pass before merge approval
   - **Cross-Platform**: Validation on Ubuntu Latest environment

2. **Code Review**: Maintainers review for:
   - Code quality and style
   - Security implications
   - Test coverage
   - Documentation completeness

3. **Testing**: Manual testing of new features
4. **Approval**: Two maintainer approvals required
5. **Merge**: Squash and merge to main branch

### CI/CD Pipeline

**Workflow Location**: `.github/workflows/rust.yml`

**Automatic Triggers:**
- Push to `main` branch
- Pull requests targeting `main` branch

**Pipeline Steps:**
```yaml
- uses: actions/checkout@v4
- name: Build
  run: cargo build --verbose
- name: Run tests
  run: cargo test --verbose
```

**Quality Requirements:**
- ✅ All 140 tests must pass
- ✅ Build must complete without errors
- ✅ No compilation failures allowed
- ✅ Ubuntu environment compatibility required

**Status Monitoring:**
- Build status badge in README.md
- GitHub Actions tab shows detailed results
- Failed builds block pull request merging

## 🐛 Issue Reporting

### Bug Reports

Use the bug report template:

```markdown
**Bug Description**
Clear description of the bug

**Steps to Reproduce**
1. Run command: `...`
2. See error: `...`

**Expected Behavior**
What should have happened

**Environment**
- OS: [e.g., Ubuntu 22.04]
- Rust version: [e.g., 1.70.0]
- Router Flood version: [e.g., 0.0.1]

**Additional Context**
- Configuration files used
- Log outputs
- Network setup details
```

### Feature Requests

```markdown
**Feature Description**
Clear description of the proposed feature

**Use Case**
Why is this feature needed?

**Proposed Implementation**
How should this be implemented?

**Safety Considerations**
How does this maintain safety and ethical usage?

**Additional Context**
Any additional information or examples
```

## 🏗️ Architecture Guidelines

### Module Organization

```
src/
├── main.rs           # Entry point - minimal, delegates to lib
├── lib.rs            # Library interface and exports
├── cli.rs            # CLI argument parsing only  
├── config.rs         # Configuration management
├── simulation.rs     # High-level orchestration
├── worker.rs         # Worker thread management
├── packet.rs         # Protocol-specific packet building
├── network.rs        # Network interface management
├── target.rs         # Target and port management
├── stats.rs          # Statistics and export
├── monitor.rs        # System monitoring
├── validation.rs     # Security validation
├── audit.rs          # Audit logging
├── error.rs          # Error types and handling
└── constants.rs      # Application constants
```

### Design Principles

1. **Separation of Concerns**: Each module has a single responsibility
2. **Safety First**: All features include safety validations
3. **Error Handling**: Comprehensive error types and propagation
4. **Async Design**: Leverages tokio for concurrency
5. **Testability**: Code designed for easy testing
6. **Documentation**: Self-documenting code with clear interfaces

### Adding New Features

1. **Security Review**: Ensure feature doesn't compromise safety
2. **Module Placement**: Place in appropriate module or create new one
3. **Error Handling**: Define appropriate error types
4. **Configuration**: Add to YAML config if user-configurable
5. **Testing**: Comprehensive test coverage
6. **Documentation**: Update README and inline docs

### Performance Considerations

- **Async/Await**: Use for I/O bound operations
- **Memory Management**: Minimize allocations in hot paths
- **Rate Limiting**: Respect configured limits
- **Resource Cleanup**: Proper cleanup in Drop implementations

## 📚 Additional Resources

### Learning Resources

- [The Rust Book](https://doc.rust-lang.org/book/)
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- [Tokio Documentation](https://tokio.rs/)
- [Network Programming with Rust](https://www.oreilly.com/library/view/network-programming-with/9781788624893/)

### Project Resources

- [GitHub Repository](https://github.com/paulshpilsher/router-flood)
- [Issue Tracker](https://github.com/paulshpilsher/router-flood/issues)
- [Project Documentation](README.md)
- [Changelog](CHANGELOG.md)

## 📞 Getting Help

- **GitHub Issues**: For bugs and feature requests
- **GitHub Discussions**: For general questions and discussions
- **Documentation**: Check README.md and inline documentation
- **Code Examples**: Look at existing tests for usage patterns

## 🙏 Recognition

Contributors will be recognized in:
- CHANGELOG.md for significant contributions
- GitHub contributors page
- Release notes for major features

Thank you for contributing to Router Flood! Your efforts help make network testing safer and more educational for everyone. 🚀
