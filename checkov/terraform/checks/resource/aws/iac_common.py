from igraph import VertexSeq


def contains_exception_tag(resource_instance: VertexSeq, resource_type: str, tag_key: str, tag_value: str) -> bool:
    """
    Checks if a resource has a specific tag with the expected value.

    Args:
        resource_instance: The resource to check.
        resource_type: The type of the resource.
        tag_key: The key of the tag to check.
        tag_value: The expected value of the tag.

    Returns:
        True if the resource has the tag with the expected value, False otherwise.
    """

    attributes = resource_instance.attributes()
    name = attributes['attr']['block_name_'].split('.')[1]  # Extract resource name
    tags = attributes['attr']['config_'][resource_type][name].get('tags')  # Access tags directly

    if not tags:
        return False

    if isinstance(tags, list):
        tags = tags[0]

    return tag_key in tags and tags[tag_key] == tag_value