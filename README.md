# ... existing content ...

## Configuration File Format

```toml
# Server configuration
server = "imap.fastmail.com"
port = 993
username = "user@fastmail.com"
target_folder = "INBOX/Newsletters"
source_folder = "INBOX"  # Optional, defaults to "INBOX"

# AI configuration
use_ai = false          # Use AI-based classification
use_hybrid = true       # Use hybrid mode (rules + AI)
model = "gemma-2b-it"   # Optional AI model name
lmstudio_url = "http://localhost:1234"  # Optional LMStudio URL
skip_confirmation = true  # Skip confirmation prompt (same as --yes)

# Optional AI prompt for customizing the AI's behavior
ai_prompt = '''
You are an email classification assistant...
'''

# Email classification rules
[[subject_rules]]
pattern = "(?i)newsletter"
description = "Company newsletters"
folder = "Newsletters"

[[subject_rules]]
pattern = "(?i)digest|weekly update"
description = "Weekly summaries"
folder = "Updates"

[[sender_rules]]
pattern = "news@example\\.com"
description = "Example.com news"
folder = "Company/News"

[[sender_rules]]
pattern = ".*@newsletter\\.com"
description = "Newsletter service"
# No folder specified, will use default target folder
```

You can specify settings either in the config file or via command line arguments. Command line arguments take precedence over config file settings. For example:

```bash
# Using only config file
email-organizer --config config.toml

# Override some config settings
email-organizer --config config.toml --target "Different/Folder" --model "different-model"

# Full command line usage (no config file)
email-organizer --server imap.example.com --username user@example.com --target Newsletters
```

# ... rest of the content ... 