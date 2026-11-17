<?php

declare(strict_types=1);

const MCP_BOOK_ID_PATTERN = '^cb_[a-f0-9]{24}$';

function mcp_coloring_book_id_schema(): array
{
    return ['type' => 'string', 'pattern' => MCP_BOOK_ID_PATTERN];
}

/** The create_coloring_book input: the idea fields plus the complete plan and one scene per drawing. */
function mcp_coloring_plan_input_schema(): array
{
    return ['type' => 'object', 'properties' => [
        'idea' => ['type' => 'string', 'minLength' => 20, 'maxLength' => 500],
        'style' => ['type' => 'string', 'enum' => array_keys(coloring_styles())],
        'audience' => ['type' => 'string', 'enum' => array_keys(coloring_audiences())],
        'age_band' => ['type' => ['string', 'null'], 'enum' => array_merge(array_keys(coloring_age_bands()), [null])],
        'mood' => ['type' => ['string', 'null'], 'enum' => array_merge(array_keys(coloring_moods()), [null])],
        'occasion' => ['type' => ['string', 'null'], 'enum' => array_merge(array_keys(coloring_occasions()), [null])],
        'character_desc' => ['type' => 'string', 'maxLength' => 200],
        'page_count' => ['type' => 'integer', 'enum' => array_keys(coloring_page_options())],
        'plan' => ['type' => 'object', 'properties' => [
            'title' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 160],
            'style_sheet' => ['type' => 'string', 'maxLength' => 500],
            'cover' => ['type' => 'object', 'properties' => [
                'title_lines' => ['type' => 'array', 'minItems' => 1, 'maxItems' => 3,
                    'items' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 32]],
                'theme' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 300],
                'background' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 200]],
                'required' => ['title_lines', 'theme', 'background'], 'additionalProperties' => false],
            'scenes' => ['type' => 'array', 'minItems' => 16, 'maxItems' => 30, 'items' => [
                'type' => 'object', 'properties' => [
                    'id' => ['type' => 'integer', 'minimum' => 1, 'maximum' => 30],
                    'main' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 160],
                    'objects' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 300],
                    'setting' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 200],
                    'description' => ['type' => 'string', 'minLength' => 1, 'maxLength' => 500]],
                'required' => ['id', 'main', 'objects', 'setting', 'description'], 'additionalProperties' => false]],
            ], 'required' => ['title', 'style_sheet', 'cover', 'scenes'], 'additionalProperties' => false],
        ], 'required' => ['idea', 'style', 'audience', 'age_band', 'mood', 'occasion', 'character_desc', 'page_count', 'plan'],
        'additionalProperties' => false];
}

function mcp_coloring_summary_schema(): array
{
    return ['type' => 'object', 'properties' => [
        'book_id' => mcp_coloring_book_id_schema(), 'title' => ['type' => 'string'], 'plan_revision' => ['type' => 'integer'],
        'state' => ['type' => 'string'], 'drawings_total' => ['type' => 'integer'],
        'next_action' => ['type' => 'object',
            'properties' => ['kind' => ['type' => 'string'], 'label' => ['type' => 'string']],
            'required' => ['kind', 'label'], 'additionalProperties' => false]],
        'required' => ['book_id', 'title', 'plan_revision', 'state', 'drawings_total', 'next_action'],
        'additionalProperties' => false];
}

function mcp_coloring_quote_schema(): array
{
    return ['type' => 'object', 'properties' => ['quote_id' => ['type' => 'string'], 'book_id' => mcp_coloring_book_id_schema(),
        'plan_revision' => ['type' => 'integer'], 'cost' => ['type' => 'integer'], 'unit' => ['type' => 'string'],
        'can_start' => ['type' => 'boolean'], 'message' => ['type' => 'string'], 'expires_at' => ['type' => 'string']],
        'required' => ['quote_id', 'book_id', 'plan_revision', 'cost', 'unit', 'can_start', 'message', 'expires_at'],
        'additionalProperties' => false];
}

function mcp_coloring_start_schema(): array
{
    return ['type' => 'object', 'properties' => ['book_id' => mcp_coloring_book_id_schema(), 'title' => ['type' => 'string'],
        'state' => ['type' => 'string'], 'charged' => ['type' => 'integer'], 'drawings_total' => ['type' => 'integer'],
        'next_action' => ['type' => 'string']],
        'required' => ['book_id', 'title', 'state', 'charged', 'drawings_total', 'next_action'],
        'additionalProperties' => false];
}

function mcp_coloring_status_schema(): array
{
    return ['type' => 'object', 'properties' => [
        'book_id' => mcp_coloring_book_id_schema(), 'title' => ['type' => 'string'], 'state' => ['type' => 'string'],
        'stage' => ['type' => 'string'], 'drawings_done' => ['type' => 'integer'], 'drawings_total' => ['type' => 'integer'],
        'cover_ready' => ['type' => 'boolean'], 'cover_revision' => ['type' => 'string'],
        'stalled' => ['type' => 'boolean'], 'waiting_to_retry' => ['type' => 'boolean'],
        'drawings' => ['type' => 'array', 'items' => ['type' => 'object']],
        'images_offset' => ['type' => 'integer'], 'images_returned' => ['type' => 'integer'],
        'more_images' => ['type' => 'boolean'], 'cover_included' => ['type' => 'boolean'], 'note' => ['type' => 'string']],
        'required' => ['book_id', 'title', 'state', 'stage', 'drawings_done', 'drawings_total', 'cover_ready', 'cover_revision',
            'stalled', 'waiting_to_retry', 'drawings', 'images_offset', 'images_returned', 'more_images', 'cover_included', 'note'],
        'additionalProperties' => false];
}

function mcp_coloring_cover_result_schema(): array
{
    return ['type' => 'object', 'properties' => ['book_id' => mcp_coloring_book_id_schema(),
        'state' => ['type' => 'string'], 'source' => ['type' => 'string'],
        'cover_revision' => ['type' => 'string'], 'message' => ['type' => 'string'],
        'cover_source_width_px' => ['type' => ['integer', 'null']],
        'cover_source_height_px' => ['type' => ['integer', 'null']],
        'cover_source_ppi_x' => ['type' => ['number', 'null']],
        'cover_source_ppi_y' => ['type' => ['number', 'null']],
        'cover_source_meets_300ppi' => ['type' => ['boolean', 'null']],
        'cover_source_resolution_note' => ['type' => 'string']],
        'required' => ['book_id', 'state', 'source', 'cover_revision', 'message', 'cover_source_width_px',
            'cover_source_height_px', 'cover_source_ppi_x', 'cover_source_ppi_y', 'cover_source_meets_300ppi',
            'cover_source_resolution_note'], 'additionalProperties' => false];
}

function mcp_coloring_export_schema(): array
{
    return ['type' => 'object', 'properties' => [
        'artifact_id' => ['type' => 'string'], 'book_id' => mcp_coloring_book_id_schema(), 'format' => ['type' => 'string'],
        'state' => ['type' => 'string'], 'export_type' => ['type' => 'string'],
        'content_hash' => ['type' => 'string'], 'cover_hash' => ['type' => 'string'],
        'is_current' => ['type' => 'boolean'], 'message' => ['type' => 'string'],
        'cover_source_width_px' => ['type' => ['integer', 'null']],
        'cover_source_height_px' => ['type' => ['integer', 'null']],
        'cover_source_ppi_x' => ['type' => ['number', 'null']],
        'cover_source_ppi_y' => ['type' => ['number', 'null']],
        'cover_source_meets_300ppi' => ['type' => ['boolean', 'null']],
        'cover_source_resolution_note' => ['type' => ['string', 'null']],
        'renderer_version' => ['type' => 'string'], 'retry_at' => ['type' => ['string', 'null']],
        'expires_at' => ['type' => ['string', 'null']], 'file_size' => ['type' => ['integer', 'null']],
        'file_sha256' => ['type' => ['string', 'null']], 'download_url' => ['type' => ['string', 'null']]],
        'required' => ['artifact_id', 'book_id', 'format', 'state', 'export_type', 'content_hash', 'cover_hash',
            'is_current', 'message', 'renderer_version', 'retry_at', 'expires_at', 'file_size', 'file_sha256', 'download_url'],
        'additionalProperties' => false];
}
