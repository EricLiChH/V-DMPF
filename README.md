# V-DMPF: C Implementation of Big-State DMPF

这是一个基于Rust代码实现的C语言版本的Big-State DMPF (Distributed Multi-Point Function)。

## 概述

DMPF是一种密码学原语，允许在多个输入点上安全地评估函数。这个实现基于"big state"方法，该方法通过维护较大的状态来优化性能，特别适用于批量操作。

## 主要特性

- **Big-State架构**: 参考Rust代码中的`big_state.rs`实现
- **批处理优化**: 支持批量操作以提高性能
- **二叉树结构**: 使用trie结构优化输入处理
- **内存安全**: 适当的内存管理和错误处理

## 文件结构

```
├── include/
│   ├── common.h      # 通用定义和辅助函数
│   ├── dpf.h         # DPF相关定义
│   ├── dmpf.h        # DMPF相关定义 (新增)
│   └── mmo.h         # MMO哈希相关
├── src/
│   ├── common.c      # 通用函数实现
│   ├── dpf.c         # DPF实现
│   ├── dmpf.c        # DMPF实现 (新增)
│   └── mmo.c         # MMO哈希实现
├── test_dmpf.c       # 测试程序
├── Makefile          # 构建配置
└── README.md         # 本文件
```

## 核心组件

### 数据结构

1. **Signs**: 维护符号位的数据结构
2. **SignsCW**: 校正字的符号数据结构
3. **BinaryTrie**: 用于输入组织的二叉树
4. **CW**: 校正字结构
5. **ConvCW**: 转换校正字结构
6. **BigStateDmpfKey**: DMPF密钥结构

### 主要函数

- `genBigStateDMPF()`: 生成DMPF密钥对
- `evalBigStateDMPF()`: 在单个点评估DMPF
- `genDMPF()`: 标准DMPF接口（委托给big state实现）

## 编译和运行

### 依赖

- GCC编译器
- OpenSSL库 (`libssl-dev`)

### 编译

```bash
make
```

### 运行测试

```bash
make test
```

### 清理

```bash
make clean
```

## 使用示例

```c
#include "include/dmpf.h"

// 初始化OpenSSL上下文
uint8_t key[16] = {0};
EVP_CIPHER_CTX *ctx = getDPFContext(key);

// 定义参数
int domain_size = 8;
int data_size = 4;
uint64_t inputs[] = {10, 50, 200};  // 必须排序
uint64_t num_inputs = 3;

// 分配密钥空间
uint8_t *k0 = malloc(1024);
uint8_t *k1 = malloc(1024);

// 生成DMPF
genDMPF(ctx, domain_size, data_size, inputs, num_inputs, k0, k1);

// 评估
uint8_t output0[4], output1[4];
evalBigStateDMPF(ctx, k0, 10, data_size, output0);
evalBigStateDMPF(ctx, k1, 10, data_size, output1);

// output0 XOR output1 应该等于输入点10的数据
```

## 实现细节

### 与Rust代码的对应关系

这个C实现直接对应Rust代码中的以下组件：

- `Signs` ↔ `big_state.rs::Signs`
- `SignsCW` ↔ `big_state.rs::SignsCW`
- `BinaryTrie` ↔ `trie.rs::BinaryTrie`
- `CW` ↔ `big_state.rs::CW`
- `ConvCW` ↔ `big_state.rs::ConvCW`

### 优化特性

1. **批处理**: 使用预计算表优化批量操作
2. **内存布局**: 优化的内存布局以提高缓存性能
3. **Tree traversal**: 高效的二叉树遍历算法

## 安全性

- 使用OpenSSL的加密安全PRG
- 适当的随机数生成
- 内存清理以防止信息泄露

## 限制

- 输入必须预先排序
- 当前实现是简化版本，可能需要进一步优化以达到生产级性能
- 密钥序列化格式是简化的

## 许可证

本实现基于原始V-DMPF项目的许可证。