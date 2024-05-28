
import os
import subprocess


def get_subdirectories(root_directory):
    subdirectories = [d for d in os.listdir(root_directory) if os.path.isdir(os.path.join(root_directory, d))]
    return subdirectories

parent_folder = '/Users/ankujais/PycharmProjects/iac_scanning/git_local/git.corp.adobe.com'
child_folders = get_subdirectories(parent_folder)

grandchild_folders = []

for child_folder in child_folders:
    # print(child_folder)
    current_subdirectories = get_subdirectories(os.path.join(parent_folder, child_folder))
    for sub_dir in current_subdirectories:
        grandchild_folders.append(os.path.join(parent_folder, child_folder, sub_dir))

grandchild_folders.sort()

for index, directory in enumerate(grandchild_folders):
    # print(index, directory)
    # if "snowplow-deployment" not in directory:
    #     continue

    # if directory == ".external_modules" or 'marketo' in directory or 'magento' in directory:
    if ".external_modules" in directory:
        continue

    if index <= 891:
        continue

    print("\n\n", index, directory)


    # print(parent_folder + '/' + directory)

    command = [
        "python",
        "main.py",
        "--directory",
        directory,
        "--check",
        # "CKV_AWS_CUSTOM_02,CKV_AWS_CUSTOM_01",
        "CKV_AWS_IDENTITY_0001,CKV_AWS_IDENTITY_0004,CKV_AWS_COMPUTE_0002,CKV_AWS_SERVICE_0001,CKV_AWS_SERVICE_0005,CKV_AWS_SERVICE_0010,CKV_AWS_STORAGE_0002,CKV_AWS_STORAGE_0008,CKV_AWS_NETWORK_0002,CKV_AWS_NETWORK_0004",
        "--download-external-modules",
        "1",
        "-o",
        "sarif"
    ]
    # Run the command
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    print(result)

    with open('results_cmd', 'a') as file:
        file.write(str(result))
        file.write("\n\n")

    print("\n\n")
