function last {
    array=("${@}")
    last_index=$(( $# - 1 ))
    last_item=${array[$last_index]}
    echo "$last_item"
}
python setup.py sdist
files=$( ls dist/*.tar.gz | sort -V )
lastfile=$( last $files )
version=${lastfile##*-}
version=${version%.tar.gz}
echo $version
twine check "$lastfile"
twine upload "$lastfile"
repo_name=func_saver
test -e .git || {
    git-repo $repo_name
    git add LICENSE.txt README.rst setup.py version.txt test.sh prod.sh $repo_name/*.py
    git commit -m 'first commit'
    git push
}
git add -u
git add $repo_name/*.py
git commit -m "$(cat version.txt)"
git push

sleep 10
python -m pip install func_saver==$version

