## 環境
- Ubuntu 24
- GCC 13

## 実行方法

1.  依存パッケージをインストール
```sh
$ sudo apt update
$ sudo apt install -y build-essential libcap-dev libseccomp-dev
```

2. Makefile があるディレクトリへ移動

3. ビルド
  - 成功すると、container_app と test_app が生成されます。
```sh
$ make
```

4. テスト実行
  - test_app を起動して、テスト結果が表示されます。
```sh
$ make test
```

5. クリーンアップ
  - ビルド生成物（.o や 実行ファイル）を削除して、ソースのみの状態に戻ります。
```sh
$ make clean
```

## ディレクトリ構成

```
.
├── Makefile
├── include
│   ├── child.h
│   ├── container.h
│   ├── resources.h
│   └── userns.h
├── src
│   ├── main.c      // clone() 呼び出しなど引数処理や最初の初期化
│   ├── child.c     // 子プロセスが実行するメイン処理
│   ├── container.c // capabilities(), syscalls(), mounts() などコンテナ構築関連
│   ├── resources.c // cgroups 設定や rlimit 設定など
│   └── userns.c    // userns(), handle_child_uid_map() など user namespace 関連
├── test
│   ├── test_main.c
│   └── test_resources.c
└── README.md
```
