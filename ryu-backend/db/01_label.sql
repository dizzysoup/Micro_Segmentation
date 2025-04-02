-- 創建標籤類型表
CREATE TABLE label_types (
    id INT AUTO_INCREMENT PRIMARY KEY,
    type_name VARCHAR(50) UNIQUE NOT NULL
);

-- 創建標籤表，包含不同類型的標籤內容
CREATE TABLE labels (
    id INT AUTO_INCREMENT PRIMARY KEY,
    label_value VARCHAR(50) NOT NULL,
    label_type_id INT,
    FOREIGN KEY (label_type_id) REFERENCES label_types(id) ON DELETE CASCADE ,
    UNIQUE (label_value, label_type_id)
);


INSERT INTO label_types (type_name) VALUES
('function'),
('application'),
('priority'),
('type'),
('environment');

-- 插入標籤內容
INSERT INTO labels (label_value, label_type_id) VALUES
('Null', (SELECT id FROM label_types WHERE type_name = 'function')),
('Web', (SELECT id FROM label_types WHERE type_name = 'function')),
('Service', (SELECT id FROM label_types WHERE type_name = 'function')),
('Database', (SELECT id FROM label_types WHERE type_name = 'function')),
('Honeypot', (SELECT id FROM label_types WHERE type_name = 'function')),
('Null', (SELECT id FROM label_types WHERE type_name = 'priority')),
('User', (SELECT id FROM label_types WHERE type_name = 'priority')),
('Admin', (SELECT id FROM label_types WHERE type_name = 'priority')),
('Null', (SELECT id FROM label_types WHERE type_name = 'type')),
('Order', (SELECT id FROM label_types WHERE type_name = 'type')),
('Shipping', (SELECT id FROM label_types WHERE type_name = 'type')),
('Payment', (SELECT id FROM label_types WHERE type_name = 'type')),
('Management', (SELECT id FROM label_types WHERE type_name = 'type')),
('Null', (SELECT id FROM label_types WHERE type_name = 'application')),
('ERP', (SELECT id FROM label_types WHERE type_name = 'application')),
('MRP', (SELECT id FROM label_types WHERE type_name = 'application')),
('PLM', (SELECT id FROM label_types WHERE type_name = 'application')),
('CAD', (SELECT id FROM label_types WHERE type_name = 'application')),
('Null', (SELECT id FROM label_types WHERE type_name = 'environment')),
('development', (SELECT id FROM label_types WHERE type_name = 'environment')),
('testing', (SELECT id FROM label_types WHERE type_name = 'environment')),
('staging', (SELECT id FROM label_types WHERE type_name = 'environment')),
('production', (SELECT id FROM label_types WHERE type_name = 'environment'));



