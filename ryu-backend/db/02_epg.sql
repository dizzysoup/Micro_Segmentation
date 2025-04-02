USE backend ; 

CREATE TABLE ep (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(15) UNIQUE NOT NULL
)

CREATE TABLE epg (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_id INT ,  
    label_type_id INT, 
    label_value_id INT,       
    FOREIGN KEY (ip_id) REFERENCES ep(id) ON  DELETE  CASCADE,     
    FOREIGN KEY (label_type_id) REFERENCES label_types(id),  
    FOREIGN KEY (label_value_id) REFERENCES labels(id) ,
    UNIQUE (ip_id, label_type_id)
);