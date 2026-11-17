<?php

declare(strict_types=1);

/*
 * Offline stand-ins for the engine's AI providers, shared by examples/offline-example.php and tools/selfcheck.php.
 * They use the engine's seam: $GLOBALS['coloring_worker_providers'] (plan, page, cover, cover_outline, kdp).
 * The "art" is a black ring on white. It proves the pipeline runs, it is not real coloring-page art.
 */

function fake_image(string $format, int $width, int $height): string
{
    $image = imagecreatetruecolor($width, $height);
    imagefill($image, 0, 0, imagecolorallocate($image, 255, 255, 255));
    imagesetthickness($image, 3);
    imageellipse($image, intdiv($width, 2), intdiv($height, 2), intdiv($width, 2), intdiv($height, 2), imagecolorallocate($image, 0, 0, 0));
    ob_start();
    $format === 'png' ? imagepng($image) : imagejpeg($image, null, 85);

    return (string) ob_get_clean();
}

function fake_save(string $relative, string $bytes): void
{
    $path = application_data_directory() . '/' . $relative;
    if (!is_dir(dirname($path))) mkdir(dirname($path), 0775, true);
    file_put_contents($path, $bytes);
}

/** Count of provider calls, so a check can prove the engine did (or did not) run. */
function fake_providers_install(): void
{
    $GLOBALS['fake_provider_calls'] = ['plan' => 0, 'page' => 0, 'cover' => 0, 'cover_outline' => 0, 'kdp' => 0];
    $GLOBALS['coloring_worker_providers'] = [
        'plan' => function (array $project): void {
            $GLOBALS['fake_provider_calls']['plan']++;
            throw new RuntimeException('The MCP create tool saves the plan; the engine plan provider must not run.');
        },
        'page' => function (array $project, int $sceneId): void {
            $GLOBALS['fake_provider_calls']['page']++;
            $path = 'coloring/' . bin2hex(random_bytes(16)) . '.png';
            fake_save($path, fake_image('png', 240, 320));
            $row = db()->prepare('SELECT pages_json FROM coloring_projects WHERE id = ?');
            $row->execute([$project['id']]);
            $pages = json_decode((string) ($row->fetchColumn() ?: '[]'), true) ?: [];
            $row->closeCursor();
            $pages[] = ['scene_id' => $sceneId, 'path' => $path, 'status' => 'done', 'tries' => 1, 'ms' => 5, 'done_at' => gmdate('Y-m-d H:i:s')];
            db()->prepare("UPDATE coloring_projects SET pages_json = ?, updated_at = datetime('now') WHERE id = ?")
                ->execute([json_encode($pages), $project['id']]);
        },
        'cover' => function (array $project): void {
            $GLOBALS['fake_provider_calls']['cover']++;
            $path = 'coloring/cover-' . bin2hex(random_bytes(12)) . '.jpg';
            fake_save($path, fake_image('jpg', 300, 400));
            db()->prepare("UPDATE coloring_projects SET cover_path = ?, cover_status = 'done', updated_at = datetime('now') WHERE id = ?")
                ->execute([$path, $project['id']]);
        },
        'cover_outline' => function (array $project): void {
            $GLOBALS['fake_provider_calls']['cover_outline']++;
            $path = 'coloring/' . bin2hex(random_bytes(16)) . '.png';
            fake_save($path, fake_image('png', 300, 400));
            db()->prepare("UPDATE coloring_projects SET cover_outline_path = ?, updated_at = datetime('now') WHERE id = ?")
                ->execute([$path, $project['id']]);
        },
        'kdp' => function (array $project): array {
            $GLOBALS['fake_provider_calls']['kdp']++;
            return ['display_title' => 'Offline Dinosaurs Coloring Book', 'subtitle' => 'A fake subtitle',
                'description' => 'A fake description.', 'keywords' => ['dinosaur coloring book'],
                'categories' => ['GAMES & ACTIVITIES / Coloring Books'], 'primary_audience' => 'Children',
                'reading_age' => '4-8 years', 'author_bio' => 'A fake bio.'];
        },
    ];
}

/** A complete create_coloring_book request: the idea fields plus a plan with one scene per drawing. */
function fake_create_request(int $drawings = 16): array
{
    $scenes = [];
    for ($i = 1; $i <= $drawings; $i++) {
        $scenes[] = ['id' => $i, 'main' => "a friendly dinosaur number $i", 'objects' => 'a basket, a blanket',
            'setting' => 'a sunny meadow', 'description' => "Dinosaur $i has a picnic."];
    }
    return ['idea' => 'A little green dinosaur hosting a picnic with friends in a sunny meadow',
        'style' => 'cute-animals', 'audience' => 'kids', 'age_band' => '4-8', 'mood' => null, 'occasion' => null,
        'character_desc' => 'a small friendly green dinosaur with round spots', 'page_count' => $drawings,
        'plan' => ['title' => 'Dinosaur Picnic', 'style_sheet' => 'Bold outlines, no shading.',
            'cover' => ['title_lines' => ['DINOSAUR', 'PICNIC'], 'theme' => 'dinosaurs at a picnic', 'background' => 'green meadow'],
            'scenes' => $scenes]];
}

/** Run the engine worker until the project is ready (bounded). */
function fake_run_worker_until_ready(int $maxPasses = 20): bool
{
    for ($pass = 0; $pass < $maxPasses; $pass++) {
        if (coloring_worker_run(5)['ready'] === 1) return true;
    }
    return false;
}
