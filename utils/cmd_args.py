import argparse
from typing import Dict


def make_cli_args(one_bar_args: Dict, two_bar_args: Dict, skip_none: bool = False):
    args = ''
    for argkey, argval in one_bar_args.items():
        if argval is None:
            if skip_none:
                continue
            arg = f' -{argkey}'
        else:
            arg = f' -{argkey} {argval}'
        args += arg
    for argkey, argval in two_bar_args.items():
        if argval is None:
            if skip_none:
                continue
            arg = f' --{argkey}'
        else:
            arg = f' --{argkey} {argval}'
        args += arg
    return args

def read_train_eval_from_config_args():
    parser = argparse.ArgumentParser()
    # Neccessary configs
    parser.add_argument('-task_name', required=True, type=str, help="Task name for data path (e.g., vul_detect/realvul_test)")
    parser.add_argument('-config', type=str, default='', help='config path of training')
    parser.add_argument('-average', required=True, type=str, help="average method for classification metric calculation")

    # Mode selection (train/test separation)
    parser.add_argument('--train-only', action='store_true', help="Run training only, skip testing")
    parser.add_argument('--test-only', action='store_true', help="Run testing only, skip training (requires pre-trained model)")
    
    # Model path (for --test-only with different model location)
    parser.add_argument('-model_path', type=str, default=None, help="Model path relative to ../data/models/extrinsic/ (e.g., vul_detect/reveal). If not specified, uses task_name.")

    # Extra configs
    parser.add_argument('-eval_script', type=str, default='eval_classification', help='test script file to do test')
    parser.add_argument('-test_batch_size', default=32, type=int)
    parser.add_argument('-test_model_names', type=str, default='model.tar.gz', help="Model names to be tested, split by comma")
    parser.add_argument('-data_file_name', type=str, default='test.json')
    parser.add_argument('-extra_averages', default=None, type=str, help="Extra average methods, split by comma")
    parser.add_argument('-extra_eval_configs', default="{}", type=str, help="Json str to configure params to eval script")

    return parser.parse_args()

def read_classification_eval_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-data_base_path', default=None, type=str, help="You can specify this full path to ignore subfolder, subset options.")
    parser.add_argument('-serial_dir', default=None, type=str, help="You can specify this full path to ignore subfolder, subset options.")

    parser.add_argument('-model_name', type=str, default='model.tar.gz')
    parser.add_argument('-data_file_name', type=str, default='test.json')
    parser.add_argument('-cuda', type=int, default=0)
    parser.add_argument('-batch_size', default=32, type=int)

    parser.add_argument('-average', required=True, type=str)
    parser.add_argument('-extra_averages', default=None, type=str, help="Extra average methods, split by comma")
    return parser.parse_args()

def read_multi_task_classification_eval_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-data_base_path', default=None, type=str, help="You can specify this full path to ignore subfolder, subset options.")
    parser.add_argument('-serial_dir', default=None, type=str, help="You can specify this full path to ignore subfolder, subset options.")
    parser.add_argument('-task_names', required=True, type=str, help="Task names joined with ','")

    parser.add_argument('-cuda', type=int, default=0)
    parser.add_argument('-model_name', type=str, default='model.tar.gz')
    parser.add_argument('-data_file_name', type=str, default='test.json')
    parser.add_argument('-batch_size', default=32, type=int)
    parser.add_argument('--all_metrics', action='store_true', default=False)

    parser.add_argument('-average', type=str, default='macro')
    parser.add_argument('-extra_averages', default=None, type=str, help="Extra average methods, split by comma")
    return parser.parse_args()
