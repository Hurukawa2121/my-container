## 環境
- Ubuntu 24
- GCC 13

## 実行方法

1.  依存パッケージをインストール
```sh
$ sudo apt update
$ sudo apt install -y build-essential libcap-dev libseccomp-dev cmake
```

2. Makefile があるディレクトリへ移動

3. ビルド
  - `container_app` と `test_app` が生成される。
```sh
$ make
```

4. テスト実行
  - `test_app` を起動し、テスト結果が表示される。
  - `root` 特権が要る可能性がある。
```sh
$ make test
```

5. クリーンアップ
  - ビルド生成物を削除する（ソースの状態に戻る）。
```sh
$ make clean
```

## ディレクトリ構成

```
.
├── CMakeLists.txt
├── build
├── include
│   ├── child.h
│   ├── container.h
│   ├── resources.h
│   └── userns.h
├── src
│   ├── main.c      // clone() 呼び出しなど引数処理や最初の初期化
│   ├── child.c     // 子プロセスが実行するメイン処理
│   ├── container.c // drop_capabilities(), restrict_syscalls(), mounts() などコンテナ構築関連
│   ├── resources.c // cgroups 設定や rlimit 設定など
│   └── userns.c    // userns(), handle_child_uid_map() など user namespace 関連
├── test
│   ├── test_main.c
│   └── test_resources.c
└── README.md
```

## Linuxコンテナの概観

#### 構成する仕組み

- **`namespaces`**（**名前空間**）
  - カーネルオブジェクト（プロセスIDやネットワークスタックなど）をホストから分離し、特定のプロセスツリーのみがアクセス可能にする仕組み。
  - 例: PID 名前空間を使うと、コンテナ内のプロセスしか見えなくなる。
- **`drop_capabilities`**
  - `root`（UID 0）の権限を機能ごとに細分化して、権限を最小限にする仕組み。
  - 例: `CAP_NET_ADMIN`（ネットワーク管理の権限）, `CAP_SYS_ADMIN`（システム操作の権限）
- **`cgroups`**（**コントロールグループ**）
  - プロセスのメモリ、CPU時間、ディスクIOなどのリソース使用を制限・管理する仕組み。
  - ファイルシステム (`/sys/fs/cgroup`) を介して制御される。
- **`setrlimit`**
  - これもリソースを制限する仕組み。
    - `cgroups` より古いが、異なる部分で補完的なリソース制限が可能。
  - 例: `ulimit` コマンド
- **`seccomp`**
  - システムコールを制限する仕組み。
  - `drop_capabilities` や `setrlimit` と同様、システムコールを通じて設定する。

#### 注意事項

- 組み合わせはトレードオフ
  - 上記の仕組みは、機能が重複したり相互に影響したりするため、ベストな組み合わせは無い。
- `user namespace`（ユーザー名前空間）の脆弱性
  - `user namespace` は root 権限を名前空間内だけで完結できる。
  - しかし、**カーネル全体の特権管理の挙動を変化させるなど、多数の脆弱性が発見されている。**
    - 参考: 
["Understanding and Hardening Linux Containers"](https://www.nccgroup.com/media/eoxggcfy/_ncc_group_understanding_hardening_linux_containers-1-1.pdf)の "8.1.6 Here Be Dragons" 
  - デフォルトで無効なことが多いが、ディストリビューションによっては限定的に有効にしている。
    - ただし、カーネルに `user namespace` が組み込まれているホストでは、使わなくても脆弱性の影響を受ける可能性がある。
- ネストして名前空間を作ることを避ける
  - 権限昇格のリスクがあるので。
