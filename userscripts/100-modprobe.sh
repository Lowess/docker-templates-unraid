#!/bin/bash

MODULES=(
  i2c_dev
)

check_module() {
  export MODULE=$1

  if lsmod | grep "$MODULE" &> /dev/null ; then
    return 0
  else
    return 1
  fi
}

main() {
  for MODULE in "${MODULES[@]}"; do
    if ! check_module "${MODULE}" ; then
      echo "📥 [📦] loading ${MODULE} using"
      modprobe "${MODULE}"
    else
      echo "✅ [📦] ${MODULE} is already loaded"
    fi
  done
}

main