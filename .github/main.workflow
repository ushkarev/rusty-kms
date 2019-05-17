workflow "Test" {
  on = "push"
  resolves = "Run tests"
}

action "Run tests" {
  uses = "./.github/test"
}
