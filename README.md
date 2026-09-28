# Maction SOP

Maction 企业运营系统：公司使命愿景与企业文化、产品与业务版图、团队与岗位职责、办公室工作指南、新员工入职清单、销售资料库、课程顾问销售 SOP、WhatsApp 模板、异议处理、CRM 规则和咨询交付 SOP。

## 访问

打开 `index.html`（或 GitHub Pages 网址），输入密码后才能看到内容。密码请向管理层索取。

页面内容用 AES-256-GCM 加密（密钥由密码经 PBKDF2-SHA256 310,000 次派生），仓库里只保存加密后的文件，没有明文。

## 更新内容

1. 修改本地的 `maction-system.html`（明文，不上传）
2. 运行 `python build.py`，输入密码，重新生成 `index.html`
3. 提交并推送 `index.html`

需要 `pip install cryptography`。
