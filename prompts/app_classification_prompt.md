# Task-Oriented Scam Application Classification Prompt

## Overview

This prompt is designed for classifying task-oriented scam mobile applications based on their app names, descriptions, and behavioral characteristics. The classification follows a hierarchical taxonomy derived from empirical analysis of 2,600+ scam samples.

---

## Classification Taxonomy

### Hierarchical Structure

```
Task-Oriented Scam Apps
├── Investment & Finance (投资理财类)
│   ├── Securities & Futures (证券期货基金)
│   ├── Cryptocurrency Trading (数字货币交易)
│   ├── Film & Art Investment (影视文化投资)
│   └── Tech Startup Funding (科技创新投资)
├── Social Welfare & Policy (社会福利政策类)
│   ├── Government Funding Programs (政府资助项目)
│   ├── Healthcare & Pension Benefits (养老医疗福利)
│   └── Refund Services (退款清退服务)
├── Task & Commission (任务佣金类)
│   ├── Shopping Rebates (购物返利)
│   └── Gig Platforms (兼职任务平台)
├── Fake Services (虚假服务类)
│   ├── Company Communication Tools (企业办公通讯)
│   ├── Customer Support (客服聊天工具)
│   └── Digital Wallets (支付钱包工具)
└── Others (其他)
    └── Unclear or mixed characteristics
```

---

## Category Definitions

### 1. Investment & Finance (投资理财类)

**Scam Characteristics**: Lure victims with promises of high returns and low risk through fake investment opportunities.

**Target Users**: 
- Seniors seeking investment opportunities
- Tech-savvy individuals interested in trading
- Stay-at-home individuals looking for income
- Potential tech investors

**App Features**: F3 (Investment Interface), F4 (Payment Gateway)

#### Sub-category 1.1: Securities & Futures (证券期货基金)

Fake securities brokerage and futures trading platforms impersonating legitimate financial institutions.

**Example App Names**:
- Institutional versions: GFZQ PRO, HXZQ PRO, 国金证券, 中信证券, 华泰证券, 东方证券, 银河证券机构版, 国泰君安
- Futures trading: 银河期货, 华融融达期货, 长江期货, 广州期货, 申万期货, 西部期货
- Fund management: 天弘基金, 易方达e钱包, 嘉实财富, 富国基金
- Private equity: 镭融私募, 红杉创投, 摩根士丹利机构版

**Recognition Patterns**:
- Contains abbreviations like "ZQ" (证券), "QH" (期货), "JJ" (基金)
- Uses legitimate financial institution names with suffixes like "PRO", "机构版", "专业版"
- Mentions investment, trading, or fund management

#### Sub-category 1.2: Cryptocurrency Trading (数字货币交易)

Fake cryptocurrency exchanges, wallets, and digital asset platforms.

**Example App Names**:
- Exchanges: Binance (fake), 币安, BitVito, OKEx Pro
- Wallets: M钱包, TB钱包, CG钱包, 百姓钱包, 云付通, 鸿蒙支付
- Digital RMB: 数字人民币上线, 数字人民币资产版, 数字人民币（国债版）
- Tokens: SHIB视界, VDS, USDT, 比特财富

**Recognition Patterns**:
- Contains crypto-related terms: BTC, ETH, USDT, 币, Coin, Token
- References blockchain, digital currency, or digital RMB
- Wallet or exchange terminology

#### Sub-category 1.3: Film & Art Investment (影视文化投资)

Investment scams disguised as film production, media company, or art collection opportunities.

**Example App Names**:
- Film/Media: 天美传媒, 星光影业, 星光影视, 东影传媒, 悦响文化, 潜流影视, 紫苏文化, 光线影视
- Media investment: 华闻传媒, 遥望科技传媒, 丝芭文化传媒
- Art collection: 佳士得, 雅昌文化, 传藏文化

**Recognition Patterns**:
- Contains terms: 传媒, 影业, 影视, 文化, 艺术
- References film projects, media production, or art collection
- Investment + entertainment industry combination

#### Sub-category 1.4: Tech Startup Funding (科技创新投资)

Investment scams leveraging emerging technology concepts like AI, blockchain, and tech startups.

**Example App Names**:
- AI platforms: DeepSeek, Grok Beta, AI STS, AIFEEX
- Blockchain: 幻核超级链, 世梅链, 星链AI, 链音
- Tech companies: 华为技术, 小米商飞, 宁德时代, 福耀科技

**Recognition Patterns**:
- Contains tech buzzwords: AI, 区块链, 链, 智能, 科技
- References well-known tech company names
- Mentions emerging technology investment

---

### 2. Social Welfare & Policy (社会福利政策类)

**Scam Characteristics**: Impersonate government agencies or policy programs to exploit victims' trust in official institutions.

**Target Users**:
- Seniors with limited digital knowledge
- Seniors concerned with healthcare issues
- Victims of previous financial losses

**App Features**: F1 (Official-looking UI), F2 (Document Display)

#### Sub-category 2.1: Government Funding Programs (政府资助项目)

Scams impersonating national policies, poverty alleviation programs, or government subsidies.

**Example App Names**:
- Rural development: 乡村振兴, 精准扶贫, 扶贫中心, 央行助农APP
- Agricultural programs: 数字农业, 农业强国, 助农工程, 新农村建设
- Government finance: 国家财政部, 财政清算, 人民央行钱库, 央行养老钱包
- National bonds: 特别国债, 国债扶贫, 中央财政部-扶贫办
- Policy initiatives: 一带一路, "十四五"规划, 新质动力, 科技强国

**Recognition Patterns**:
- Contains government/official terms: 国家, 中央, 央行, 财政, 政府
- References national policies or initiatives
- Mentions poverty alleviation, rural development, or subsidies

#### Sub-category 2.2: Healthcare & Pension Benefits (养老医疗福利)

Scams targeting seniors with fake healthcare, pension, or social security benefits.

**Example App Names**:
- Elderly care: 一脉养老, 夕阳红, 银发蓝海, 银发增福
- Healthcare: 妙手云医, 日医学馆, 健康中国, 智慧学堂
- Insurance: 中国人寿, 民族社保, 一老一小

**Recognition Patterns**:
- Contains elderly-related terms: 养老, 银发, 夕阳, 老年
- References healthcare, medical services, or pension
- Mentions social security or insurance benefits

#### Sub-category 2.3: Refund Services (退款清退服务)

Scams targeting previous fraud victims with fake refund or debt recovery services.

**Example App Names**:
- Consumer protection: 全国12315平台, 12315, 315管家, 中消协会
- Refund operations: 清退行动, 收尾行动, 债速清, 民债清查
- Recovery platforms: 中国追损行动, 债无忧, 人民化债

**Recognition Patterns**:
- Contains refund/recovery terms: 退款, 清退, 追损, 维权
- References consumer protection agencies (12315, 315)
- Mentions debt recovery or fraud compensation

---

### 3. Task & Commission (任务佣金类)

**Scam Characteristics**: Lure victims with easy money through task completion, requiring upfront deposits or fees.

**Target Users**:
- Homemakers seeking side income
- Freelancers and gig workers

**App Features**: F1 (Task List), F2 (Reward Display), F3 (Progress Tracking), F4 (Payment Integration)

#### Sub-category 3.1: Shopping Rebates (购物返利)

Scams offering cashback or rebates through fake e-commerce platforms.

**Example App Names**:
- E-commerce: TEMU国际, 京东惠购, 拼多多商业联盟, 淘天集团
- Rebate platforms: 趣闲赚, 赚客-手机赚钱, 闲赚侠, 每天赚点
- Point collection: 蛋蛋赚, 答题赚钱花, 全民来瓜分, 赚步

**Recognition Patterns**:
- Contains earning terms: 赚, 返利, 返现, 优惠
- References major e-commerce platforms
- Mentions shopping, rebates, or cashback

#### Sub-category 3.2: Gig Platforms (兼职任务平台)

Fake gig economy platforms offering paid tasks or micro-jobs.

**Example App Names**:
- Task platforms: 赏帮赚, 趣闲兼职, 闲易赚兼职, 砖王兼职
- Video watching: 刷宝短视频, 喜赚好剧, 星赚乐看, 聊剧赚
- Walking/fitness: 赚步, 健行天下
- Other gigs: 人海战术, 全民置顶, 星星V剧

**Recognition Patterns**:
- Contains gig terms: 兼职, 任务, 赏金, 刷单
- Promises payment for simple tasks
- References watching videos, walking, or completing surveys

---

### 4. Fake Services (虚假服务类)

**Scam Characteristics**: Disguise as legitimate service tools to facilitate fraud or fund transfers.

**Target Users**:
- Job-seeking students and graduates
- Victims of shopping data leaks
- Money mules helping launder funds

**App Features**: Varies by sub-category

#### Sub-category 4.1: Company Communication Tools (企业办公通讯)

Fake enterprise software used to establish trust and facilitate fraud operations.

**Example App Names**:
- AI assistants: AI管家, AI云枢, Ai办公助手, kimi办公, Chat助手
- Office tools: Office助理, 企信通讯, 云办公系统, 移动办公
- Communication: NsChat, FlyChat, 新闲聊, 蓝莺IM, Yo信

**Recognition Patterns**:
- Contains office/enterprise terms: 办公, 企业, 通讯, 协同
- References AI, cloud, or productivity tools
- Mentions team communication or collaboration

#### Sub-category 4.2: Customer Support (客服聊天工具)

Fake customer service platforms used to impersonate legitimate companies.

**Example App Names**:
- Customer service: 蚂蚁云客服, 快牛电商客服, 淘金云客服, 唯品会云客服
- Instant messaging: 畅聊, 波聊, TKchat, 商联通讯

**Recognition Patterns**:
- Contains customer service terms: 客服, 在线客服, 云客服
- References major e-commerce platforms + customer service
- Mentions chat or instant messaging

#### Sub-category 4.3: Digital Wallets (支付钱包工具)

Fake payment applications used to steal funds or credentials.

**Example App Names**:
- Third-party payment: JDPay, 京东支付, 抖音支付, 腾讯支付, 小米支付
- Online wallets: 网商钱包, 微众钱包, 有钱花, 招联金融
- Enterprise payment: Card-Pay, Nexa Pay, 易币付, 智天支付

**Recognition Patterns**:
- Contains payment terms: 支付, Pay, 钱包, Wallet
- References major platform payment services
- Mentions financial transactions or transfers

---

### 5. Others (其他)

**Description**: Applications with unclear descriptions, missing case data, or characteristics spanning multiple categories.

**Target Users**: Various user groups

**Recognition Patterns**:
- Cannot be clearly classified into above categories
- Contains mixed or ambiguous features
- Insufficient information for accurate classification

---

## Classification Prompt Template

```
You are an expert in mobile application security and fraud detection. Your task is to classify the following scam application into one of the predefined categories based on its name and available information.

### Classification Categories

1. **Investment & Finance** (投资理财类)
   - Securities & Futures: Fake brokerage/trading platforms
   - Cryptocurrency Trading: Fake crypto exchanges/wallets
   - Film & Art Investment: Entertainment industry investment scams
   - Tech Startup Funding: Emerging technology investment scams

2. **Social Welfare & Policy** (社会福利政策类)
   - Government Funding Programs: Fake government subsidy programs
   - Healthcare & Pension Benefits: Fake elderly care/healthcare services
   - Refund Services: Fake refund/debt recovery platforms

3. **Task & Commission** (任务佣金类)
   - Shopping Rebates: Fake cashback/rebate platforms
   - Gig Platforms: Fake task/gig economy platforms

4. **Fake Services** (虚假服务类)
   - Company Communication Tools: Fake enterprise software
   - Customer Support: Fake customer service platforms
   - Digital Wallets: Fake payment applications

5. **Others** (其他)
   - Unclear or mixed characteristics

### App Information

**App Name**: {APP_NAME}
**Package Name**: {PACKAGE_NAME} (if available)
**Description**: {DESCRIPTION} (if available)

### Instructions

1. Analyze the app name for keywords and patterns
2. Consider common abbreviations (e.g., ZQ=证券, QH=期货)
3. Match against the category recognition patterns
4. Assign to the most appropriate main category and sub-category
5. If uncertain, classify as "Others" and explain the ambiguity

### Output Format

Category: [Main Category]
Sub-category: [Sub-category]
Confidence: [High/Medium/Low]
Reasoning: [Brief explanation of classification decision]
```

---

## Batch Classification Format

For batch processing multiple applications:

```json
{
  "apps": [
    {
      "app_name": "GFZQ PRO",
      "package_name": "com.gfzq.pro",
      "description": "证券交易平台"
    },
    {
      "app_name": "乡村振兴",
      "package_name": "com.xczx.app",
      "description": "国家政策项目"
    }
  ]
}
```

Expected output:

```json
{
  "classifications": [
    {
      "app_name": "GFZQ PRO",
      "category": "Investment & Finance",
      "sub_category": "Securities & Futures",
      "confidence": "High",
      "reasoning": "GFZQ is abbreviation for 广发证券 (Guangfa Securities), PRO suffix indicates institutional version"
    },
    {
      "app_name": "乡村振兴",
      "category": "Social Welfare & Policy",
      "sub_category": "Government Funding Programs",
      "confidence": "High",
      "reasoning": "乡村振兴 (Rural Revitalization) is a national policy initiative name"
    }
  ]
}
```

---

## Category Distribution Reference

Based on empirical analysis:

| Category | Proportion |
|----------|------------|
| Investment & Finance | 47.5% |
| Social Welfare & Policy | 27.7% |
| Task & Commission | 9.7% |
| Fake Services | 13.7% |
| Others | 2.4% |

---

## Notes

1. **Abbreviation Handling**: Chinese Pinyin abbreviations are common (e.g., GFZQ = 广发证券, HXZQ = 华夏证券)
2. **Legitimate Brand Impersonation**: Many scam apps impersonate legitimate companies by adding suffixes like "PRO", "机构版", "专业版"
3. **Multi-category Cases**: Some apps may exhibit features of multiple categories; classify based on primary scam mechanism
4. **Context Sensitivity**: Classification accuracy improves with additional context (package name, description, behavioral data)

---

## Contact

For questions about the classification methodology: [yc_guo@stu.hit.edu.cn](mailto:yc_guo@stu.hit.edu.cn)
