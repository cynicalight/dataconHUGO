run :
	hugo
	cd public
	echo "11" > 11.txt
	git add .
	git commit -m "update"
	git push origin master