# Classification Prompts

This directory contains prompts for classifying task-oriented scam applications.

## Files

| File | Description |
|------|-------------|
| `app_classification_prompt.md` | Main classification prompt (English) |
| `app_classification_prompt_zh.md` | 分类提示词（中文版） |

## Usage

These prompts can be used with Large Language Models (LLMs) to classify scam applications based on their names, descriptions, and characteristics.

## Classification Taxonomy

The classification follows a hierarchical taxonomy with **5 main categories** and **12 sub-categories**:

| Category | Sub-categories | Proportion |
|----------|---------------|------------|
| Investment & Finance | Securities & Futures, Cryptocurrency, Film & Art Investment, Tech Startup | 47.5% |
| Social Welfare & Policy | Government Funding, Healthcare & Pension, Refund Services | 27.7% |
| Task & Commission | Shopping Rebates, Gig Platforms | 9.7% |
| Fake Services | Company Communication, Customer Support, Digital Wallets | 13.7% |
| Others | Unclear or mixed types | 2.4% |

## Quick Reference

### Main Categories (5)

1. **Investment & Finance (投资理财类)** - Fake investment platforms promising high returns
2. **Social Welfare & Policy (社会福利政策类)** - Impersonating government programs
3. **Task & Commission (任务佣金类)** - Fake gig economy and rebate platforms
4. **Fake Services (虚假服务类)** - Fake utility tools for facilitating fraud
5. **Others (其他)** - Unclear or mixed characteristics

### Sub-categories (12)

| # | Sub-category | Parent Category |
|---|--------------|-----------------|
| 1 | Securities & Futures (证券期货基金) | Investment & Finance |
| 2 | Cryptocurrency Trading (数字货币交易) | Investment & Finance |
| 3 | Film & Art Investment (影视文化投资) | Investment & Finance |
| 4 | Tech Startup Funding (科技创新投资) | Investment & Finance |
| 5 | Government Funding Programs (政府资助项目) | Social Welfare & Policy |
| 6 | Healthcare & Pension Benefits (养老医疗福利) | Social Welfare & Policy |
| 7 | Refund Services (退款清退服务) | Social Welfare & Policy |
| 8 | Shopping Rebates (购物返利) | Task & Commission |
| 9 | Gig Platforms (兼职任务平台) | Task & Commission |
| 10 | Company Communication Tools (企业办公通讯) | Fake Services |
| 11 | Customer Support (客服聊天工具) | Fake Services |
| 12 | Digital Wallets (支付钱包工具) | Fake Services |

## Contact

For questions about the classification methodology, please contact: [yc_guo@stu.hit.edu.cn](mailto:yc_guo@stu.hit.edu.cn)
