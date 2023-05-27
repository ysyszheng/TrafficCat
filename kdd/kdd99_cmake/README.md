
## Build instructions to Linux (tested on Ubuntu)
1. Create a folder to temporal build files<br/>
   `cd kdd/kdd99_cmake`<br/>
   `mkdir build-files`<br/><br/>
2. Enter in the folder and compile the cache<br/>
  `cd build-files`<br/>
   `cmake -DCMAKE_BUILD_TYPE=Debug -G "CodeBlocks - Unix Makefiles" ..`<br/><br/>
3. Exit the folder of build cache and compile the project<br/>
  `cd ..`<br/>
  `cmake --build ./build-files --target kdd99extractor -- -j 4`<br/><br/>
4. Path to compiled project is:<br/>
  `build-files/src/kdd99extractor`<br/><br/>
5. mv to TrafficCat/kdd/ is:<br/>
  `mv build-files/src/kdd99extractor ../`<br/><br/>

