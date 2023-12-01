from __future__ import annotations

import logging
import os
from typing import List, Dict, Tuple, Callable, Any

from checkov.cloudformation import cfn_utils
from checkov.cloudformation.context_parser import ContextParser as CfnContextParser
from checkov.common.bridgecrew.check_type import CheckType
from checkov.common.parallelizer.parallel_runner import parallel_runner
from checkov.common.util.secrets import omit_secret_value_from_checks
from checkov.serverless.base_registry import EntityDetails
from checkov.serverless.parsers.context_parser import ContextParser as SlsContextParser
from checkov.cloudformation.checks.resource.registry import cfn_registry
from checkov.serverless.checks.complete.registry import complete_registry
from checkov.serverless.checks.custom.registry import custom_registry
from checkov.serverless.checks.function.registry import function_registry
from checkov.serverless.checks.layer.registry import layer_registry
from checkov.serverless.checks.package.registry import package_registry
from checkov.serverless.checks.plugin.registry import plugin_registry
from checkov.serverless.checks.provider.registry import provider_registry
from checkov.serverless.checks.service.registry import service_registry
from checkov.common.runners.base_runner import BaseRunner, filter_ignored_paths
from checkov.runner_filter import RunnerFilter
from checkov.common.output.record import Record
from checkov.common.output.report import Report
from checkov.common.output.extra_resource import ExtraResource
from checkov.serverless.parsers.parser import parse
from checkov.common.parsers.node import DictNode
from checkov.serverless.parsers.parser import CFN_RESOURCES_TOKEN

SLS_FILE_MASK = os.getenv(
    "CKV_SLS_FILE_MASK", "serverless.yml,serverless.yaml").split(",")

MULTI_ITEM_SECTIONS = [
    ("functions", function_registry),
    ("layers", layer_registry)
]
SINGLE_ITEM_SECTIONS = [
    ("custom", custom_registry),
    ("package", package_registry),
    ("plugins", plugin_registry),
    ("provider", provider_registry),
    ("service", service_registry)
]


class Runner(BaseRunner[None, None, None]):
    check_type = CheckType.SERVERLESS  # noqa: CCE003  # a static attribute

    def __init__(self) -> None:
        super().__init__(file_names=SLS_FILE_MASK)

    def run(
        self,
        root_folder: str | None,
        external_checks_dir: list[str] | None = None,
        files: list[str] | None = None,
        runner_filter: RunnerFilter | None = None,
        collect_skip_comments: bool = True,
    ) -> Report:
        runner_filter = runner_filter or RunnerFilter()
        if not runner_filter.show_progress_bar:
            self.pbar.turn_off_progress_bar()

        report = Report(self.check_type)
        files_list = []
        filepath_fn = None
        if external_checks_dir:
            for directory in external_checks_dir:
                function_registry.load_external_checks(directory)

        if files:
            files_list = [file for file in files if os.path.basename(file) in SLS_FILE_MASK]

        if root_folder:
            filepath_fn = lambda f: f'/{os.path.relpath(f, os.path.commonprefix((root_folder, f)))}'
            for root, d_names, f_names in os.walk(root_folder):
                # Don't walk in to "node_modules" directories under the root folder. If –for some reason–
                # scanning one of these is desired, it can be directly specified.
                if "node_modules" in d_names:
                    d_names.remove("node_modules")

                filter_ignored_paths(root, d_names, runner_filter.excluded_paths)
                filter_ignored_paths(root, f_names, runner_filter.excluded_paths)
                for file in f_names:
                    if file in SLS_FILE_MASK:
                        full_path = os.path.join(root, file)
                        if "/." not in full_path:
                            # skip temp directories
                            files_list.append(full_path)

        definitions, definitions_raw = get_files_definitions(files_list, filepath_fn)

        # Filter out empty files that have not been parsed successfully
        definitions = {k: v for k, v in definitions.items() if v}
        definitions_raw = {k: v for k, v in definitions_raw.items() if k in definitions.keys()}

        self.pbar.initiate(len(definitions))

        for sls_file, sls_file_data in definitions.items():
            self.pbar.set_additional_data({'Current File Scanned': os.path.relpath(sls_file, root_folder)})
            # There are a few cases here. If -f was used, there could be a leading / because it's an absolute path,
            # or there will be no leading slash; root_folder will always be none.
            # If -d is used, root_folder will be the value given, and -f will start with a / (hardcoded above).
            # The goal here is simply to get a valid path to the file (which sls_file does not always give).
            if sls_file[0] == '/':
                path_to_convert = (root_folder + sls_file) if root_folder else sls_file
            else:
                path_to_convert = (os.path.join(root_folder, sls_file)) if root_folder else sls_file

            file_abs_path = os.path.abspath(path_to_convert)

            if not isinstance(sls_file_data, DictNode):
                continue

            if CFN_RESOURCES_TOKEN in sls_file_data and isinstance(sls_file_data[CFN_RESOURCES_TOKEN], DictNode):
                cf_sub_template = sls_file_data[CFN_RESOURCES_TOKEN]
                cf_sub_resources = cf_sub_template.get("Resources")
                if cf_sub_resources and isinstance(cf_sub_resources, dict):
                    cf_context_parser = CfnContextParser(sls_file, cf_sub_template, definitions_raw[sls_file])
                    logging.debug(f"Template Dump for {sls_file}: {sls_file_data}")
                    cf_context_parser.evaluate_default_refs()
                    for resource_name, resource in cf_sub_resources.items():
                        if not isinstance(resource, dict):
                            continue
                        cf_resource_id = cf_context_parser.extract_cf_resource_id(resource, resource_name)
                        if not cf_resource_id:
                            # Not Type attribute for resource
                            continue
                        report.add_resource(f'{file_abs_path}:{cf_resource_id}')
                        entity_lines_range, entity_code_lines = cf_context_parser.extract_cf_resource_code_lines(
                            resource)
                        if entity_lines_range and entity_code_lines:
                            skipped_checks = CfnContextParser.collect_skip_comments(entity_code_lines)
                            # TODO - Variable Eval Message!
                            variable_evaluations: dict[str, Any] = {}

                            entity_dict = {resource_name: resource}
                            results = cfn_registry.scan(sls_file, entity_dict, skipped_checks, runner_filter)
                            tags = cfn_utils.get_resource_tags(entity_dict, cfn_registry)
                            if results:
                                for check, check_result in results.items():
                                    censored_code_lines = omit_secret_value_from_checks(
                                        check=check,
                                        check_result=check_result,
                                        entity_code_lines=entity_code_lines,
                                        entity_config=resource,
                                        resource_attributes_to_omit=runner_filter.resource_attr_to_omit
                                    )
                                    record = Record(check_id=check.id, bc_check_id=check.bc_id, check_name=check.name, check_result=check_result,
                                                    code_block=censored_code_lines, file_path=sls_file,
                                                    file_line_range=entity_lines_range,
                                                    resource=cf_resource_id, evaluations=variable_evaluations,
                                                    check_class=check.__class__.__module__, file_abs_path=file_abs_path,
                                                    entity_tags=tags, severity=check.severity)
                                    record.set_guideline(check.guideline)
                                    report.add_record(record=record)
                            else:
                                report.extra_resources.add(
                                    ExtraResource(
                                        file_abs_path=file_abs_path,
                                        file_path=sls_file,
                                        resource=cf_resource_id,
                                    )
                                )

            sls_context_parser = SlsContextParser(sls_file, sls_file_data, definitions_raw[sls_file])

            # Sub-sections that have multiple items under them
            for token, registry in MULTI_ITEM_SECTIONS:
                template_items = sls_file_data.get(token)
                if not template_items or not isinstance(template_items, dict):
                    continue
                for item_name, item_content in template_items.items():
                    if not isinstance(item_content, DictNode):
                        continue
                    entity_lines_range, entity_code_lines = sls_context_parser.extract_code_lines(item_content)
                    if entity_lines_range and entity_code_lines:
                        skipped_checks = CfnContextParser.collect_skip_comments(entity_code_lines)
                        variable_evaluations = {}
                        if token == "functions":  # nosec
                            # "Enriching" copies things like "environment" and "stackTags" down into the
                            # function data from the provider block since logically that's what serverless
                            # does. This allows checks to see what the complete data would be.
                            sls_context_parser.enrich_function_with_provider(item_name)
                        entity = EntityDetails(sls_context_parser.provider_type, item_content)
                        results = registry.scan(sls_file, entity, skipped_checks, runner_filter)
                        tags = cfn_utils.get_resource_tags(entity, registry)  # type:ignore[arg-type]
                        if results:
                            for check, check_result in results.items():
                                censored_code_lines = omit_secret_value_from_checks(
                                    check=check,
                                    check_result=check_result,
                                    entity_code_lines=entity_code_lines,
                                    entity_config=item_content,
                                    resource_attributes_to_omit=runner_filter.resource_attr_to_omit
                                )
                                record = Record(check_id=check.id, check_name=check.name, check_result=check_result,
                                                code_block=censored_code_lines, file_path=sls_file,
                                                file_line_range=entity_lines_range,
                                                resource=item_name, evaluations=variable_evaluations,
                                                check_class=check.__class__.__module__, file_abs_path=file_abs_path,
                                                entity_tags=tags, severity=check.severity)
                                record.set_guideline(check.guideline)
                                report.add_record(record=record)
                        else:
                            report.extra_resources.add(
                                ExtraResource(
                                    file_abs_path=file_abs_path,
                                    file_path=sls_file,
                                    resource=item_name,
                                )
                            )
            # Sub-sections that are a single item
            for token, registry in SINGLE_ITEM_SECTIONS:
                item_content = sls_file_data.get(token)
                if not item_content:
                    continue
                entity_lines_range, entity_code_lines = sls_context_parser.extract_code_lines(item_content)
                if not entity_lines_range:
                    entity_lines_range, entity_code_lines = sls_context_parser.extract_code_lines(sls_file_data)

                skipped_checks = CfnContextParser.collect_skip_comments(entity_code_lines or [])
                variable_evaluations = {}
                entity = EntityDetails(sls_context_parser.provider_type, item_content)
                results = registry.scan(sls_file, entity, skipped_checks, runner_filter)
                tags = cfn_utils.get_resource_tags(entity, registry)  # type:ignore[arg-type]
                if results:
                    for check, check_result in results.items():
                        censored_code_lines = omit_secret_value_from_checks(
                            check=check,
                            check_result=check_result,
                            entity_code_lines=entity_code_lines or [],
                            entity_config=item_content,
                            resource_attributes_to_omit=runner_filter.resource_attr_to_omit
                        )
                        record = Record(
                            check_id=check.id,
                            check_name=check.name,
                            check_result=check_result,
                            code_block=censored_code_lines,
                            file_path=sls_file,
                            file_line_range=entity_lines_range or [0, 0],
                            resource=token,
                            evaluations=variable_evaluations,
                            check_class=check.__class__.__module__,
                            file_abs_path=file_abs_path,
                            entity_tags=tags,
                            severity=check.severity,
                        )
                        record.set_guideline(check.guideline)
                        report.add_record(record=record)
                else:
                    report.extra_resources.add(
                        ExtraResource(
                            file_abs_path=file_abs_path,
                            file_path=sls_file,
                            resource=token,
                        )
                    )

            # "Complete" checks
            # NOTE: Ignore code content, no point in showing (could be long)
            entity_lines_range, entity_code_lines = sls_context_parser.extract_code_lines(sls_file_data)
            if entity_lines_range:
                skipped_checks = CfnContextParser.collect_skip_comments(entity_code_lines or [])
                variable_evaluations = {}
                entity = EntityDetails(sls_context_parser.provider_type, sls_file_data)
                results = complete_registry.scan(sls_file, entity, skipped_checks, runner_filter)
                tags = cfn_utils.get_resource_tags(entity, complete_registry)  # type:ignore[arg-type]
                if results:
                    for check, check_result in results.items():
                        record = Record(check_id=check.id, check_name=check.name, check_result=check_result,
                                        code_block=[],              # Don't show, could be large
                                        file_path=sls_file,
                                        file_line_range=entity_lines_range,
                                        resource="complete",        # Weird, not sure what to put where
                                        evaluations=variable_evaluations,
                                        check_class=check.__class__.__module__, file_abs_path=file_abs_path,
                                        entity_tags=tags, severity=check.severity)
                        record.set_guideline(check.guideline)
                        report.add_record(record=record)
                else:
                    report.extra_resources.add(
                        ExtraResource(
                            file_abs_path=file_abs_path,
                            file_path=sls_file,
                            resource="complete",
                        )
                    )
            self.pbar.update()
        self.pbar.close()
        return report


def get_files_definitions(
    files: List[str], filepath_fn: Callable[[str], str] | None = None
) -> Tuple[Dict[str, dict[str, Any]], Dict[str, List[Tuple[int, str]]]]:
    results = parallel_runner.run_function(_parallel_parse, files)
    definitions = {}
    definitions_raw = {}
    for file, result in results:
        if result:
            path = filepath_fn(file) if filepath_fn else file
            definitions[path], definitions_raw[path] = result

    return definitions, definitions_raw


def _parallel_parse(f: str) -> tuple[str, tuple[dict[str, Any], list[tuple[int, str]]] | None]:
    """Thin wrapper to return filename with parsed content"""
    return f, parse(f)
