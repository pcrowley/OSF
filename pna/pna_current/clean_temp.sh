clear
echo "Removing all files ending with '~'"
rm -v $(find *|grep \~)
echo "Done!"
