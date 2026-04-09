from __future__ import annotations

import json
from pathlib import Path

import matplotlib
import numpy as np
from sklearn import manifold

matplotlib.use('Agg')
import matplotlib.pyplot as plt

try:
    import seaborn as sns
except ModuleNotFoundError:
    sns = None

if sns is not None:
    sns.set(rc={'figure.figsize': (11.7, 8.27)})
else:
    plt.rcParams['figure.figsize'] = (11.7, 8.27)


FEATURE_BASENAME = 'test_last_hidden_state_vectors'
RAW_MODEL_EVAL_DIRNAME = 'raw_model_eval'
COMBINED_TEST_TSNE_BASENAME = 'combined_test_last_hidden_state_vectors'
DEFAULT_TSNE_FIGSIZE = (10, 10)
DEFAULT_TSNE_MARKER_SIZE = 3
DEFAULT_TSNE_MARKER_LINEWIDTH = 0.2
DEFAULT_TSNE_MARKER_ALPHA = 0.35
DEFAULT_TSNE_MARKER_ZORDER = 2
DEFAULT_TSNE_SHUFFLE_SEED = 0
BEFORE_NON_VULN_TSNE_COLOR = '#31a354'
AFTER_NON_VULN_TSNE_COLOR = '#3182bd'
BEFORE_VULN_TSNE_COLOR = '#cb181d'
AFTER_VULN_TSNE_COLOR = '#f16913'
SINGLE_TSNE_TITLE = 'PDBERT t-SNE on SARD-Juliet SA TracePair'
COMBINED_TSNE_TITLE = 'PDBERT t-SNE on SARD-Juliet SA TracePair (Combined)'
DEFAULT_LEGEND_FONT_SIZE = 12
DEFAULT_LEGEND_Y = 1.03


def build_feature_artifact_paths(model_dir: str | Path) -> tuple[Path, Path, Path]:
    base_path = Path(model_dir) / FEATURE_BASENAME
    return (
        base_path.with_suffix('.npz'),
        Path(f'{base_path}.jpeg'),
        Path(f'{base_path}-tsne-features.json'),
    )


def _resolve_group_style(stage_label: str, target_value: int) -> dict:
    if stage_label == 'Before Fine-tuned' and target_value == 0:
        return {'color': BEFORE_NON_VULN_TSNE_COLOR}
    if stage_label == 'After Fine-tuned' and target_value == 0:
        return {'color': AFTER_NON_VULN_TSNE_COLOR}
    if stage_label == 'Before Fine-tuned' and target_value == 1:
        return {'color': BEFORE_VULN_TSNE_COLOR}
    return {'color': AFTER_VULN_TSNE_COLOR}


def _build_group_spec(
    stage_label: str,
    target_value: int,
    *,
    model_value: int | None = None,
    zorder: int | None = None,
) -> dict:
    style = _resolve_group_style(stage_label, target_value)
    spec = {
        'label': f"{stage_label} / {'Vuln' if target_value == 1 else 'Non-Vuln'}",
        'target_value': target_value,
        'marker': 'o',
        'facecolor': style['color'],
        'edgecolor': style['color'],
        'alpha': DEFAULT_TSNE_MARKER_ALPHA,
        'linewidth': DEFAULT_TSNE_MARKER_LINEWIDTH,
    }
    if model_value is not None:
        spec['model_value'] = model_value
    spec['zorder'] = DEFAULT_TSNE_MARKER_ZORDER if zorder is None else zorder
    return spec


def _resolve_single_group_specs(title: str | None) -> list[dict]:
    title_str = str(title) if title is not None else ''
    is_raw_model = RAW_MODEL_EVAL_DIRNAME in title_str
    stage_label = 'Before Fine-tuned' if is_raw_model else 'After Fine-tuned'
    return [
        _build_group_spec(stage_label, 0),
        _build_group_spec(stage_label, 1),
    ]


def _resolve_paired_group_specs() -> list[dict]:
    return [
        _build_group_spec(
            'Before Fine-tuned',
            1,
            model_value=1,
        ),
        _build_group_spec(
            'After Fine-tuned',
            1,
            model_value=0,
        ),
        _build_group_spec(
            'Before Fine-tuned',
            0,
            model_value=1,
        ),
        _build_group_spec(
            'After Fine-tuned',
            0,
            model_value=0,
        ),
    ]


def _scatter_groups(
    X: np.ndarray,
    labels: np.ndarray,
    group_specs: list[dict],
    *,
    model_source: np.ndarray | None = None,
) -> None:
    draw_queue = []
    for spec in group_specs:
        mask = labels == spec['target_value']
        if model_source is not None:
            mask &= model_source == spec['model_value']

        point_indices = np.flatnonzero(mask)
        if point_indices.size == 0:
            continue

        plt.scatter(
            [],
            [],
            marker=spec['marker'],
            facecolors=spec['facecolor'],
            edgecolors=spec['edgecolor'],
            c=None,
            s=DEFAULT_TSNE_MARKER_SIZE,
            alpha=spec['alpha'],
            linewidths=spec['linewidth'],
            label=spec['label'],
            zorder=spec.get('zorder', DEFAULT_TSNE_MARKER_ZORDER),
        )
        for point_index in point_indices:
            draw_queue.append((point_index, spec))

    if not draw_queue:
        return

    rng = np.random.default_rng(DEFAULT_TSNE_SHUFFLE_SEED)
    for queue_index in rng.permutation(len(draw_queue)):
        point_index, spec = draw_queue[queue_index]
        point = X[point_index]
        plt.scatter(
            point[0],
            point[1],
            marker=spec['marker'],
            facecolors=spec['facecolor'],
            edgecolors=spec['edgecolor'],
            c=None,
            s=DEFAULT_TSNE_MARKER_SIZE,
            alpha=spec['alpha'],
            linewidths=spec['linewidth'],
            label='_nolegend_',
            zorder=spec.get('zorder', DEFAULT_TSNE_MARKER_ZORDER),
        )


def _apply_tsne_layout(
    plot_title: str | None,
    *,
    legend_ncol: int,
    top_margin: float = 0.9,
    legend_fontsize: int = DEFAULT_LEGEND_FONT_SIZE,
) -> None:
    axes = plt.gca()
    axes.set_box_aspect(1)
    plt.xticks([]), plt.yticks([])
    if plot_title is not None:
        plt.title(plot_title)
    plt.legend(
        frameon=False,
        loc='lower center',
        bbox_to_anchor=(0.5, DEFAULT_LEGEND_Y),
        ncol=legend_ncol,
        borderaxespad=0.0,
        fontsize=legend_fontsize,
        markerscale=5.0,
        handletextpad=0.6,
        columnspacing=1.4,
    )
    plt.tight_layout(rect=(0, 0, 1, top_margin))


def _fit_embedding(X_org: np.ndarray) -> np.ndarray | None:
    if X_org.shape[0] < 2:
        return None

    perplexity = min(30, X_org.shape[0] - 1)
    tsne = manifold.TSNE(n_components=2, init='pca', random_state=0, perplexity=perplexity)
    print('Fitting TSNE!')
    X = tsne.fit_transform(X_org)
    x_min, x_max = np.min(X, 0), np.max(X, 0)
    denom = np.where((x_max - x_min) == 0, 1, (x_max - x_min))
    return (X - x_min) / denom


def plot_embedding(X_org, y, title=None, new=True) -> bool:
    X_org = np.asarray(X_org)
    Y = np.asarray(y)

    if X_org.shape[0] < 2:
        print(f'Skipping TSNE for {title}: need at least 2 samples, got {X_org.shape[0]}')
        return False

    cache_path = str(title) + '-tsne-features.json'
    if not new and Path(cache_path).exists():
        with open(cache_path, 'r', encoding='utf-8') as file:
            _x, _y = json.load(file)
        X = np.array(_x)
        Y = np.array(_y)
    else:
        X = _fit_embedding(X_org)
        if X is None:
            print(f'Skipping TSNE for {title}: need at least 2 samples, got {X_org.shape[0]}')
            return False
        with open(cache_path, 'w', encoding='utf-8') as file_:
            json.dump([X.tolist(), Y.tolist()], file_)

    if sns is not None:
        sns.set(style='white')
    plt.figure(figsize=DEFAULT_TSNE_FIGSIZE, edgecolor='black')
    _scatter_groups(X, Y, _resolve_single_group_specs(title))
    _apply_tsne_layout(
        SINGLE_TSNE_TITLE if title is not None else None,
        legend_ncol=2,
        top_margin=0.9,
    )
    plt.savefig(str(title) + '.jpeg', dpi=1000)
    plt.close()
    return True


def plot_paired_embedding(
    fine_X_org,
    fine_y,
    raw_X_org,
    raw_y,
    title=None,
    new=True,
) -> bool:
    fine_X_org = np.asarray(fine_X_org)
    fine_y = np.asarray(fine_y)
    raw_X_org = np.asarray(raw_X_org)
    raw_y = np.asarray(raw_y)

    combined_features = np.concatenate([fine_X_org, raw_X_org], axis=0)
    combined_labels = np.concatenate([fine_y, raw_y], axis=0)
    model_source = np.concatenate(
        [
            np.zeros(fine_X_org.shape[0], dtype=np.int64),
            np.ones(raw_X_org.shape[0], dtype=np.int64),
        ],
        axis=0,
    )

    cache_path = str(title) + '-tsne-features.json'
    if not new and Path(cache_path).exists():
        with open(cache_path, 'r', encoding='utf-8') as file:
            payload = json.load(file)
        X = np.array(payload['embedding'])
        combined_labels = np.array(payload['labels'])
        model_source = np.array(payload['model_source'])
    else:
        X = _fit_embedding(combined_features)
        if X is None:
            print(
                f'Skipping paired TSNE for {title}: '
                f'need at least 2 samples, got {combined_features.shape[0]}'
            )
            return False
        with open(cache_path, 'w', encoding='utf-8') as file_:
            json.dump(
                {
                    'embedding': X.tolist(),
                    'labels': combined_labels.tolist(),
                    'model_source': model_source.tolist(),
                },
                file_,
            )

    if sns is not None:
        sns.set(style='white')
    plt.figure(figsize=DEFAULT_TSNE_FIGSIZE, edgecolor='black')
    _scatter_groups(
        X,
        combined_labels,
        _resolve_paired_group_specs(),
        model_source=model_source,
    )
    _apply_tsne_layout(
        COMBINED_TSNE_TITLE if title is not None else None,
        legend_ncol=2,
        top_margin=0.86,
    )
    plt.savefig(str(title) + '.jpeg', dpi=1000)
    plt.close()
    return True


def load_feature_artifact(feature_npz_path: Path) -> tuple[np.ndarray, np.ndarray]:
    with np.load(feature_npz_path) as payload:
        return np.asarray(payload['features']), np.asarray(payload['labels'])


def validate_paired_feature_artifacts(
    fine_features: np.ndarray,
    fine_labels: np.ndarray,
    raw_features: np.ndarray,
    raw_labels: np.ndarray,
    *,
    fine_feature_npz_path: Path,
    raw_feature_npz_path: Path,
) -> None:
    if fine_features.ndim != 2 or raw_features.ndim != 2:
        raise ValueError(
            'Expected 2D feature arrays for paired TSNE: '
            f'{fine_feature_npz_path} -> {fine_features.shape}, '
            f'{raw_feature_npz_path} -> {raw_features.shape}'
        )

    if fine_features.shape[1] != raw_features.shape[1]:
        raise ValueError(
            'Fine-tuned and raw test feature dimensions do not match: '
            f'{fine_feature_npz_path} -> {fine_features.shape}, '
            f'{raw_feature_npz_path} -> {raw_features.shape}'
        )

    if fine_features.shape[0] != raw_features.shape[0]:
        raise ValueError(
            'Fine-tuned and raw test sample counts do not match: '
            f'{fine_feature_npz_path} -> {fine_features.shape[0]}, '
            f'{raw_feature_npz_path} -> {raw_features.shape[0]}'
        )

    if fine_labels.shape != raw_labels.shape or not np.array_equal(fine_labels, raw_labels):
        raise ValueError(
            'Fine-tuned and raw test labels do not match: '
            f'{fine_feature_npz_path} -> {fine_labels.shape}, '
            f'{raw_feature_npz_path} -> {raw_labels.shape}'
        )


def maybe_export_paired_test_tsne(raw_feature_npz_path: Path) -> tuple[Path | None, Path | None]:
    raw_feature_npz_path = Path(raw_feature_npz_path)
    raw_output_dir = raw_feature_npz_path.parent
    if raw_output_dir.name != RAW_MODEL_EVAL_DIRNAME:
        return None, None

    fine_output_dir = raw_output_dir.parent
    fine_feature_npz_path, _, _ = build_feature_artifact_paths(fine_output_dir)
    if not fine_feature_npz_path.exists():
        print(
            'Skipping paired TSNE: fine-tuned test hidden states not found under '
            f'{fine_output_dir}'
        )
        return None, None

    fine_features, fine_labels = load_feature_artifact(fine_feature_npz_path)
    raw_features, raw_labels = load_feature_artifact(raw_feature_npz_path)

    validate_paired_feature_artifacts(
        fine_features,
        fine_labels,
        raw_features,
        raw_labels,
        fine_feature_npz_path=fine_feature_npz_path,
        raw_feature_npz_path=raw_feature_npz_path,
    )

    combined_output_base = fine_output_dir / COMBINED_TEST_TSNE_BASENAME
    combined_tsne_image_path = Path(f'{combined_output_base}.jpeg')
    combined_tsne_cache_path = Path(f'{combined_output_base}-tsne-features.json')

    tsne_generated = plot_paired_embedding(
        fine_features,
        fine_labels,
        raw_features,
        raw_labels,
        title=str(combined_output_base),
        new=True,
    )
    if not tsne_generated:
        return None, None

    print(f'Paired t-SNE 이미지 저장 완료: {combined_tsne_image_path}')
    print(f'Paired t-SNE 캐시 저장 완료: {combined_tsne_cache_path}')
    return combined_tsne_image_path, combined_tsne_cache_path
