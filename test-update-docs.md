# Update Documentation Tool Implementation

## Test Cases

### 1. Create New Document
```json
{
  "action": "create",
  "file_path": "test/new-document.md", 
  "content": "# Test Document\n\nThis is a test document created via the update_docs tool.",
  "commit_message": "Add test document via MCP tool",
  "pr_title": "Test: Add new document via update_docs tool",
  "pr_description": "Testing the new update_docs MCP tool functionality"
}
```

### 2. Update Existing Document
```json
{
  "action": "update",
  "file_path": "processes/sales/existing-doc.md",
  "content": "---\nprocess_code: SALES-001\ntitle: Updated Sales Process\n---\n\n# Updated Sales Process\n\nThis document has been updated via the MCP tool.",
  "commit_message": "Update sales process documentation",
  "pr_title": "Update sales process with new requirements"
}
```

### 3. Direct Commit (No PR)
```json
{
  "action": "update",
  "file_path": "quick-actions/test-action.md",
  "content": "# Test Quick Action\n\nDirect commit without PR creation.",
  "commit_message": "Direct update to quick action doc"
}
```

## Integration Workflow

1. **Search for existing docs**: Use `search_sop_docs` with `include_content: true`
2. **Get current content**: Content returned from search
3. **Modify content**: User edits the content
4. **Update via MCP**: Use `update_docs` tool to create PR

## Expected Behavior

- ✅ Creates new branch with timestamp
- ✅ Commits file changes with provided message  
- ✅ Creates PR when `pr_title` provided
- ✅ Returns branch, commit SHA, and PR details
- ✅ Handles both create and update operations
- ✅ Preserves existing file SHA for updates

## Configuration Requirements

- `GITHUB_TOKEN`: Must have `contents:write` and `pull_requests:write` permissions
- `GITHUB_SOP_OWNER`: Repository owner (defaults to "ASISolutions")
- `GITHUB_SOP_REPO`: Repository name (defaults to "docs") 
- `GITHUB_API_BASE`: GitHub API base URL (optional, defaults to "https://api.github.com")

## Tool Response Format

```json
{
  "success": true,
  "action": "create|update",
  "file_path": "path/to/file.md",
  "branch": "docs-update-1234567890",
  "commit_sha": "abc123...",
  "repository": "ASISolutions/docs",
  "pull_request": {
    "url": "https://github.com/ASISolutions/docs/pull/123",
    "number": 123,
    "title": "PR title"
  },
  "message": "Documentation created and pull request created successfully..."
}
```