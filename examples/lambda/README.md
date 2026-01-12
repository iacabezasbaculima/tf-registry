# Introduction

This is an AWS Lambda function example that uses the `tf-registry` lib crate.

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install)
- [Cargo Lambda](https://www.cargo-lambda.info/guide/installation.html)

## Building

To build the project, run `cargo lambda build`.

Read more about building your lambda function in [the Cargo Lambda documentation](https://www.cargo-lambda.info/commands/build.html).

## Testing

If you want to run integration tests locally, you can use the `cargo lambda watch`.

First, run `cargo lambda watch` to start a local server.

Second, call the function directly with cURL or any other HTTP client. For example:

```bash
curl http://localhost:9000/.well-known/terraform.json

# Response
{"providers.v1":"/terraform/providers/v1/"}                                      
```

Read more about running the local server in [the Cargo Lambda documentation for the `watch` command](https://www.cargo-lambda.info/commands/watch.html).
