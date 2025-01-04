cmake_minimum_required(VERSION 3.10)
project(container_app C)

# C言語のバージョン、コンパイルオプション
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -O2 -g")

# インクルードディレクトリ (MakefileのINCLUDES相当)
include_directories(${CMAKE_SOURCE_DIR}/include)

# ------------------------------------------------------------
# 1. メインバイナリ (container_app) の構築
# ------------------------------------------------------------
# ソースファイル (MakefileのSOURCES_MAINに該当)
set(SOURCES_MAIN
    src/main.c
    src/child.c
    src/container.c
    src/resources.c
    src/userns.c
)

add_executable(container_app ${SOURCES_MAIN})
# リンクライブラリ (MakefileのLDFLAGS相当: -lcap -lseccomp)
target_link_libraries(container_app cap seccomp)

# ------------------------------------------------------------
# 2. テストバイナリ (test_app) の構築
# ------------------------------------------------------------
# テスト用ソース (MakefileのSOURCES_TESTに該当)
set(SOURCES_TEST
    test/main.c
    test/resources.c
)

# テスト時に src/resources.c が必要なので一緒にコンパイル
# ライブラリ化してリンクしても良いかも）
add_executable(test_app ${SOURCES_TEST} src/resources.c)
target_link_libraries(test_app cap seccomp)

# ------------------------------------------------------------
# 3. make test 相当: テストを実行するターゲット
# ------------------------------------------------------------
add_custom_target(test
    COMMAND ./test_app
    DEPENDS test_app
    COMMENT "Run tests with test_app"
)


