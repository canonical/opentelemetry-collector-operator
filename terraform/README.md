# Terraform module for opentelemetry-collector-k8s


This is a Terraform module facilitating the deployment of opentelemetry-collector charm, using the [Terraform juju provider](https://github.com/juju/terraform-provider-juju/). For more information, refer to the provider [documentation](https://registry.terraform.io/providers/juju/juju/latest/docs).


## Requirements
This module requires a `juju` model to be available. Refer to the [usage section](#usage) below for more details.

## API

### Inputs
The module offers the following configurable inputs:

| Name | Type | Description | Required |
| - | - | - | - |
| `app_name`| string | Application name | opentelemetry-collector |
| `channel`| string | Channel that the charm is deployed from |  |
| `config`| map(string) | Map of the charm configuration options | {} |
| `constraints`| string | Constraints for the Juju deployment| arch=amd64 |
| `model`| string | Name of the model that the charm is deployed on |  |
| `revision`| number | Revision number of the charm name | null |
| `storage_directives`| map(string) | Map of storage used by the application, which defaults to 1 GB, allocated by Juju | {} |
| `units`| number | Number of units to deploy | 1 |

### Outputs
Upon applied, the module exports the following outputs:

| Name | Description |
| - | - |
| `app_name`|  Application name |
| `provides`|  Map of `provides` endpoints |
| `requires`|  Map of `requires` endpoints |

## Usage

Users should ensure that Terraform is aware of the `juju_model` dependency of the charm module.

To deploy this module with its needed dependency, you can run `terraform apply -var="model_name=<MODEL_NAME>" -auto-approve`
