#!/usr/bin/env python
# encoding: utf-8

import os
import shutil
import git
import pathlib
from collections import namedtuple

Repo = namedtuple("Repo", "url name")

REPOS = [
	Repo("https://github.com/Yara-Rules/rules", "yara-rules"),
]

#Delete official repo and clone it to retrieve last yara rules
def update_yara_rule_clone(repo):
	repo_dir = os.path.join("repos", repo.name)
	if not os.path.isdir(repo_dir):
		git.Git().clone("https://github.com/Yara-Rules/rules.git", repo_dir)
		return

	repo = git.Repo(repo_dir)
	o = repo.remotes.origin
	o.pull()

SKIP = [
	"rules/Mobile_Malware",
	"MALW_TinyShell_Backdoor_gen.yar",
	"RomeoFoxtrot_mod.yara.error"
]

#Get all Yara files
def get_yara_files(folder):
	all_yara_files = []
	for file in sorted(pathlib.Path(folder).rglob("*.yar")):
		if 'index' in file.name or 'deprecated' in file.parts:
			continue
		if file.name in SKIP or str(file.parent) in SKIP:
			continue
		all_yara_files.append(str(file))
	return all_yara_files

UNSUPPORTED_IMPORTS = [
	"math",
	"cuckoo",
	"hash",
	"imphash",
]

def contains_unsupported_import(rule_fn):
	with open(rule_fn) as fd:
		yara_in_file = fd.read()
	for i in UNSUPPORTED_IMPORTS:
		if f'import "{i}"' in yara_in_file:
			return True

	return False

#Filter Yara files with import math, imphash function and is__osx rule TODO
def remove_incompatible_imports(files):
	return [f for f in files if not contains_unsupported_import(f)]

#Remove private rule is__elf {
def remove_iself_duplicates(files):
	yara_files_filtered = []
	first_elf = True
	to_delete = False
	for yara_file in files:
		with open(yara_file, 'r') as fd:
			yara_in_file = fd.readlines()
			for line in yara_in_file:
				if line.strip() == "private rule is__elf {":
					if first_elf:
						first_elf = False
					else:
						to_delete = True
				if not to_delete:
					yara_files_filtered.append(line)
				if (not first_elf) and line.strip() == "}":
					to_delete = False
			yara_files_filtered.append("\n")
	return yara_files_filtered

def dump_in_file(all_rules):
	with open("all_yara_rules.yar", 'w') as fd:
		fd.write(''.join(all_rules))

def main():
	root_yara = "repos"
	for repo in REPOS:
		update_yara_rule_clone(repo)
	all_yara_files = get_yara_files(root_yara)
	all_yara_filered_1 = remove_incompatible_imports(all_yara_files)
	all_yara_filered_2 = remove_iself_duplicates(all_yara_filered_1)
	dump_in_file(all_yara_filered_2)

# Main body
if __name__ == '__main__':
	main()
