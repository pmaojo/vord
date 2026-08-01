flowchart LR
  benches("benches")
  benches_corpus("benches/corpus")
  benches_src("benches/src")
  bin_cli("bin/cli")
  bin_lsp("bin/lsp")
  core_agent("core/agent")
  core_agent_policy("core/agent-policy")
  core_ast("core/ast")
  core_cfg("core/cfg")
  core_crap("core/crap")
  core_duplication("core/duplication")
  core_import_graph("core/import-graph")
  core_profiles("core/profiles")
  core_remediation("core/remediation")
  core_rules_engine("core/rules-engine")
  core_swarm("core/swarm")
  core_symbols("core/symbols")
  core_taint("core/taint")
  fixtures("fixtures")
  fixtures_hexagon("fixtures/hexagon")
  infra_azure("infra/azure")
  infra_bitbucket("infra/bitbucket")
  infra_fs("infra/fs")
  infra_github("infra/github")
  infra_gitlab("infra/gitlab")
  infra_llm("infra/llm")
  infra_memory("infra/memory")
  infra_pdf("infra/pdf")
  npm("npm")
  npm_bin("npm/bin")
  parsers_treesitter_adapter("parsers/treesitter-adapter")
  parsers_treesitter_bash("parsers/treesitter-bash")
  parsers_treesitter_c("parsers/treesitter-c")
  parsers_treesitter_cpp("parsers/treesitter-cpp")
  parsers_treesitter_csharp("parsers/treesitter-csharp")
  parsers_treesitter_css("parsers/treesitter-css")
  parsers_treesitter_dockerfile("parsers/treesitter-dockerfile")
  parsers_treesitter_elixir("parsers/treesitter-elixir")
  parsers_treesitter_go("parsers/treesitter-go")
  parsers_treesitter_groovy("parsers/treesitter-groovy")
  parsers_treesitter_hcl("parsers/treesitter-hcl")
  parsers_treesitter_html("parsers/treesitter-html")
  parsers_treesitter_java("parsers/treesitter-java")
  parsers_treesitter_json("parsers/treesitter-json")
  parsers_treesitter_kotlin("parsers/treesitter-kotlin")
  parsers_treesitter_lua("parsers/treesitter-lua")
  parsers_treesitter_php("parsers/treesitter-php")
  parsers_treesitter_python("parsers/treesitter-python")
  parsers_treesitter_ruby("parsers/treesitter-ruby")
  parsers_treesitter_rust("parsers/treesitter-rust")
  parsers_treesitter_scala("parsers/treesitter-scala")
  parsers_treesitter_swift("parsers/treesitter-swift")
  parsers_treesitter_tokens("parsers/treesitter-tokens")
  parsers_treesitter_typescript("parsers/treesitter-typescript")
  parsers_treesitter_xml("parsers/treesitter-xml")
  parsers_treesitter_yaml("parsers/treesitter-yaml")
  rulesets_a11y("rulesets/a11y")
  rulesets_ai_agent("rulesets/ai-agent")
  rulesets_architecture("rulesets/architecture")
  rulesets_code_smells("rulesets/code-smells")
  rulesets_ddd("rulesets/ddd")
  rulesets_go("rulesets/go")
  rulesets_iac("rulesets/iac")
  rulesets_mutation("rulesets/mutation")
  rulesets_owasp("rulesets/owasp")
  rulesets_php("rulesets/php")
  rulesets_python("rulesets/python")
  rulesets_react("rulesets/react")
  rulesets_reactive("rulesets/reactive")
  rulesets_rust("rulesets/rust")
  rulesets_secrets("rulesets/secrets")
  rulesets_typescript("rulesets/typescript")
  scripts("scripts")
  benches --> bin_cli
  benches --> core_ast
  benches --> core_rules_engine
  benches --> parsers_treesitter_rust
  benches_corpus --> core_ast
  benches_corpus --> core_duplication
  benches_corpus --> core_profiles
  benches_corpus --> core_rules_engine
  benches_corpus --> core_taint
  benches_src --> benches
  benches_src --> bin_cli
  bin_cli --> core_agent
  bin_cli --> core_agent_policy
  bin_cli --> core_ast
  bin_cli --> core_import_graph
  bin_cli --> core_remediation
  bin_cli --> core_rules_engine
  bin_cli --> core_swarm
  bin_cli --> infra_fs
  bin_cli --> infra_github
  bin_cli --> infra_llm
  bin_cli --> infra_memory
  bin_cli --> infra_pdf
  bin_cli --> parsers_treesitter_bash
  bin_cli --> parsers_treesitter_c
  bin_cli --> parsers_treesitter_cpp
  bin_cli --> parsers_treesitter_csharp
  bin_cli --> parsers_treesitter_css
  bin_cli --> parsers_treesitter_dockerfile
  bin_cli --> parsers_treesitter_elixir
  bin_cli --> parsers_treesitter_go
  bin_cli --> parsers_treesitter_groovy
  bin_cli --> parsers_treesitter_hcl
  bin_cli --> parsers_treesitter_html
  bin_cli --> parsers_treesitter_java
  bin_cli --> parsers_treesitter_json
  bin_cli --> parsers_treesitter_kotlin
  bin_cli --> parsers_treesitter_lua
  bin_cli --> parsers_treesitter_php
  bin_cli --> parsers_treesitter_python
  bin_cli --> parsers_treesitter_ruby
  bin_cli --> parsers_treesitter_rust
  bin_cli --> parsers_treesitter_scala
  bin_cli --> parsers_treesitter_swift
  bin_cli --> parsers_treesitter_typescript
  bin_cli --> parsers_treesitter_xml
  bin_cli --> parsers_treesitter_yaml
  bin_cli --> rulesets_a11y
  bin_cli --> rulesets_ai_agent
  bin_cli --> rulesets_architecture
  bin_cli --> rulesets_code_smells
  bin_cli --> rulesets_ddd
  bin_cli --> rulesets_go
  bin_cli --> rulesets_iac
  bin_cli --> rulesets_mutation
  bin_cli --> rulesets_owasp
  bin_cli --> rulesets_php
  bin_cli --> rulesets_python
  bin_cli --> rulesets_react
  bin_cli --> rulesets_reactive
  bin_cli --> rulesets_rust
  bin_cli --> rulesets_secrets
  bin_cli --> rulesets_typescript
  bin_lsp --> bin_cli
  bin_lsp --> core_ast
  bin_lsp --> core_rules_engine
  bin_lsp --> infra_memory
  core_agent --> core_agent_policy
  core_agent --> core_profiles
  core_agent_policy --> core_profiles
  core_cfg --> core_ast
  core_crap --> core_ast
  core_duplication --> core_ast
  core_import_graph --> core_ast
  core_import_graph --> core_rules_engine
  core_remediation --> core_ast
  core_remediation --> core_rules_engine
  core_rules_engine --> core_ast
  core_rules_engine --> core_crap
  core_rules_engine --> core_duplication
  core_rules_engine --> core_profiles
  core_symbols --> core_ast
  core_taint --> core_ast
  core_taint --> core_cfg
  infra_azure --> core_rules_engine
  infra_bitbucket --> core_rules_engine
  infra_fs --> core_agent
  infra_fs --> core_ast
  infra_fs --> core_remediation
  infra_fs --> core_rules_engine
  infra_fs --> core_swarm
  infra_github --> core_agent
  infra_github --> core_rules_engine
  infra_gitlab --> core_rules_engine
  infra_llm --> core_agent
  infra_llm --> core_remediation
  infra_memory --> core_remediation
  infra_memory --> core_rules_engine
  infra_pdf --> core_rules_engine
  parsers_treesitter_adapter --> core_ast
  parsers_treesitter_adapter --> core_duplication
  parsers_treesitter_adapter --> core_rules_engine
  parsers_treesitter_adapter --> parsers_treesitter_tokens
  parsers_treesitter_bash --> core_ast
  parsers_treesitter_bash --> parsers_treesitter_adapter
  parsers_treesitter_c --> core_ast
  parsers_treesitter_c --> parsers_treesitter_adapter
  parsers_treesitter_cpp --> core_ast
  parsers_treesitter_cpp --> parsers_treesitter_adapter
  parsers_treesitter_csharp --> core_ast
  parsers_treesitter_csharp --> parsers_treesitter_adapter
  parsers_treesitter_css --> core_ast
  parsers_treesitter_css --> parsers_treesitter_adapter
  parsers_treesitter_dockerfile --> core_ast
  parsers_treesitter_dockerfile --> core_rules_engine
  parsers_treesitter_elixir --> core_ast
  parsers_treesitter_elixir --> core_duplication
  parsers_treesitter_elixir --> core_rules_engine
  parsers_treesitter_elixir --> parsers_treesitter_tokens
  parsers_treesitter_go --> core_ast
  parsers_treesitter_go --> parsers_treesitter_adapter
  parsers_treesitter_groovy --> core_ast
  parsers_treesitter_groovy --> parsers_treesitter_adapter
  parsers_treesitter_hcl --> core_ast
  parsers_treesitter_hcl --> parsers_treesitter_adapter
  parsers_treesitter_html --> core_ast
  parsers_treesitter_html --> parsers_treesitter_adapter
  parsers_treesitter_java --> core_ast
  parsers_treesitter_java --> parsers_treesitter_adapter
  parsers_treesitter_json --> core_ast
  parsers_treesitter_json --> parsers_treesitter_adapter
  parsers_treesitter_kotlin --> core_ast
  parsers_treesitter_kotlin --> parsers_treesitter_adapter
  parsers_treesitter_lua --> core_ast
  parsers_treesitter_lua --> parsers_treesitter_adapter
  parsers_treesitter_php --> core_ast
  parsers_treesitter_php --> parsers_treesitter_adapter
  parsers_treesitter_python --> core_ast
  parsers_treesitter_python --> parsers_treesitter_adapter
  parsers_treesitter_ruby --> core_ast
  parsers_treesitter_ruby --> parsers_treesitter_adapter
  parsers_treesitter_rust --> core_ast
  parsers_treesitter_rust --> parsers_treesitter_adapter
  parsers_treesitter_scala --> core_ast
  parsers_treesitter_scala --> parsers_treesitter_adapter
  parsers_treesitter_swift --> core_ast
  parsers_treesitter_swift --> parsers_treesitter_adapter
  parsers_treesitter_tokens --> core_duplication
  parsers_treesitter_typescript --> core_ast
  parsers_treesitter_typescript --> core_duplication
  parsers_treesitter_typescript --> core_rules_engine
  parsers_treesitter_typescript --> parsers_treesitter_adapter
  parsers_treesitter_xml --> core_ast
  parsers_treesitter_xml --> parsers_treesitter_adapter
  parsers_treesitter_yaml --> core_ast
  parsers_treesitter_yaml --> parsers_treesitter_adapter
  rulesets_a11y --> core_ast
  rulesets_a11y --> core_rules_engine
  rulesets_ai_agent --> core_ast
  rulesets_ai_agent --> core_rules_engine
  rulesets_ai_agent --> core_taint
  rulesets_architecture --> core_ast
  rulesets_architecture --> core_import_graph
  rulesets_architecture --> core_rules_engine
  rulesets_code_smells --> core_ast
  rulesets_code_smells --> core_cfg
  rulesets_code_smells --> core_rules_engine
  rulesets_code_smells --> core_symbols
  rulesets_ddd --> core_ast
  rulesets_ddd --> core_import_graph
  rulesets_ddd --> core_rules_engine
  rulesets_ddd --> core_symbols
  rulesets_go --> core_ast
  rulesets_go --> core_rules_engine
  rulesets_iac --> core_ast
  rulesets_iac --> core_rules_engine
  rulesets_mutation --> core_ast
  rulesets_mutation --> core_rules_engine
  rulesets_owasp --> core_ast
  rulesets_owasp --> core_rules_engine
  rulesets_owasp --> core_taint
  rulesets_php --> core_ast
  rulesets_php --> core_rules_engine
  rulesets_python --> core_ast
  rulesets_python --> core_rules_engine
  rulesets_react --> core_ast
  rulesets_react --> core_rules_engine
  rulesets_react --> core_symbols
  rulesets_reactive --> core_ast
  rulesets_reactive --> core_rules_engine
  rulesets_rust --> core_ast
  rulesets_rust --> core_rules_engine
  rulesets_rust --> core_taint
  rulesets_secrets --> core_ast
  rulesets_secrets --> core_rules_engine
  rulesets_typescript --> core_ast
  rulesets_typescript --> core_rules_engine
  classDef cycle fill:#fde2e2,stroke:#c0392b,stroke-width:2px;
