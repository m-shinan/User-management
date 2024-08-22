package controllers

import (
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/m-shinan/week6/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type UserControls struct {
	DB *gorm.DB
}

type JwtToken struct {
	Name  string
	Email string
	jwt.RegisteredClaims
}

var keyString = []byte("SuperSecret")

func GenerateToken(username string) (string, error) {
	var token JwtToken = JwtToken{}
	token = JwtToken{Name: username}
	tockenstring := jwt.NewWithClaims(jwt.SigningMethodHS256, token)
	jwtToken, err := tockenstring.SignedString(keyString)
	if err != nil {
		return "", err
	}
	return jwtToken, nil
}

// var Temp models.Users

func NoCache() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		c.Header("Pragma", "no-cache,no-store, must-revalidate")
		c.Header("Expires", "0")
		c.Next()
	}
}

func (ctrl *UserControls) ShowSingUpPage(c *gin.Context) {
	c.HTML(http.StatusOK, "singup.html", nil)
}

func (ctrl *UserControls) Validate(c *gin.Context) {
	var user models.Users
	user.First_Name = c.PostForm("firstname")
	user.Last_Name = c.PostForm("lastname")
	user.UserName = c.PostForm("username")
	user.Email = c.PostForm("email")
	user.Password = c.PostForm("password")

	if user.First_Name == "" || user.Last_Name == "" || user.UserName == "" || user.Email == "" || user.Password == "" {
		c.HTML(http.StatusOK, "singup.html", gin.H{
			"Errors": "please fill all details",
		})
		return
	}
	var existingUser models.Users
	result := ctrl.DB.Where("user_name = ?", user.UserName).First(&existingUser)
	if result.RowsAffected > 0 {
		c.HTML(http.StatusOK, "singup.html", gin.H{
			"Errors": "Username already exists",
		})
		return
	}

	result = ctrl.DB.Where("email = ?", user.Email).First(&existingUser)
	if result.RowsAffected > 0 {
		c.HTML(http.StatusOK, "singup.html", gin.H{
			"Errors": "email already exist",
		})
		return
	}

	// Hash the password before storing it in the database
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		// Handle error
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"Message": "Error hashing password",
		})
		return
	}
	user.Password = string(hashedPassword)

	ctrl.DB.Create(&user)
	c.Redirect(http.StatusSeeOther, "/login")
}

func (ctrl *UserControls) Login(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", nil)
}

// func AuthMiddleware() gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		session := sessions.Default(c)
// 		username := session.Get("username")
// 		if username == nil {
// 			c.Next() // Proceed to the next middleware or route handler
// 		} else {
// 			c.Redirect(http.StatusMovedPermanently, "/Home") // Redirect to home page if user is authenticated
// 			c.Abort() // Abort further processing
// 		}
// 	}
// }

// func AuthMiddleware() gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		session := sessions.Default(c)
// 		username := session.Get("username")
// 		if username == nil {
// 			c.Next() // Proceed to the next middleware or route handler
// 		} else {
// 			c.Redirect(http.StatusMovedPermanently, "/Home") // Redirect to home page if user is authenticated
// 			c.Abort()                                        // Abort further processing
// 		}
// 	}
// }

// func AuthMiddleware() gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		session := sessions.Default(c)
// 		username := session.Get("username")
// 		if username == nil {
// 			// Proceed to the next middleware or route handler
// 			c.Next()
// 			return
// 		}
// 		// User is authenticated, proceed to the home page
// 		c.HTML(http.StatusOK, "homepage2.html", nil)
// 	}
// }

//	func AuthMiddleware() gin.HandlerFunc {
//		return func(c *gin.Context) {
//			session := sessions.Default(c)
//			username := session.Get("username")
//			if username == nil {
//				c.Redirect(http.StatusSeeOther, "/login") // Redirect to login page if user is not authenticated
//				c.Abort()
//				return
//			}
//			// Proceed to the next middleware or route handler if user is authenticated
//			c.Next()
//		}
//	}
// func AuthMiddleware() gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		session := sessions.Default(c)
// 		username := session.Get("username")
// 		fmt.Println(username)
// 		if username != nil {
// 			// User is already authenticated, redirect to home page
// 			c.Redirect(http.StatusSeeOther, "/Home")
// 			c.Next() // Stop further processing

// 		} else {
// 			c.Redirect(http.StatusSeeOther, "/login")
// 		}

// User is not authenticated, proceed to next middleware or route handler

// 	}
// }

func (ctrl *UserControls) Loginvalidation(c *gin.Context) {
	type user struct {
		username string
		password string
	}
	var data user
	var temp models.Users
	data.username = c.PostForm("username")
	data.password = c.PostForm("password")
	// if err := c.ShouldBind(&data); err != nil {
	// 	c.HTML(http.StatusBadRequest, "login.html", gin.H{
	// 		"Errors": "Username not found",
	// 	})

	Username = c.PostForm("username")
	if data.username == "" || data.password == "" {
		c.HTML(http.StatusBadRequest, "login.html", gin.H{
			"Errors": "please enter user name and password",
		})
		return
	}

	result := ctrl.DB.Where("user_name = ?", data.username).First(&temp)
	if result.Error != nil {
		c.HTML(http.StatusBadRequest, "login.html", gin.H{
			"Errors": "Username not found",
		})
		return
	}

	// Compare the hashed password with the provided password using bcrypt
	err := bcrypt.CompareHashAndPassword([]byte(temp.Password), []byte(data.password))
	if err != nil {
		c.HTML(http.StatusOK, "login.html", gin.H{
			"Errors": "Invalid password",
		})
		return
	}

	token, err := GenerateToken(temp.UserName)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"Message": "Error generating token",
		})
		return
	}

	c.Set("username", temp.UserName)

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", token, 36000*24*30, "", "", false, true)
	c.Redirect(http.StatusMovedPermanently, "/Home")
}

var Username string

// func (ctrl *UserControls) Homepage(c *gin.Context) {

// 	temp, err := c.Cookie("Authorization")
// 	if err != nil || temp == "" {
// 		c.Redirect(http.StatusSeeOther, "/login")
// 		return
// 	}
// 	c.HTML(http.StatusOK, "homepage2.html", gin.H{
// 		"message": Username,
// 	})

// }

func (ctrl *UserControls) Homepage(c *gin.Context) {
	temp, err := c.Cookie("Authorization")
	if err != nil || temp == "" {
		c.Redirect(http.StatusSeeOther, "/login") // Redirect to login page if user is not authenticated
		return
	}
	// c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	// c.Header("Pragma", "no-cache")
	// c.Header("Expires", "0")

	c.HTML(http.StatusOK, "homepage2.html", gin.H{
		"message": Username,
	})
}

func (ctrl *UserControls) LogginOut(c *gin.Context) {

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", "", -1, "", "", false, true)

	c.HTML(http.StatusOK, "login.html", nil)
}

func (ctrl *UserControls) Adminloginpage(c *gin.Context) {

	c.HTML(http.StatusOK, "adminlogin.html", nil)
}

func (ctrl *UserControls) AdminValidation(c *gin.Context) {
	type admin struct {
		Name     string
		Password string
	}
	var user admin
	user.Name = c.PostForm("username")
	user.Password = c.PostForm("password")

	if user.Name == "" || user.Password == "" {
		c.HTML(http.StatusOK, "adminlogin.html", gin.H{
			"Errors": "please fill details",
		})
		return
	}

	if user.Name != "mshinan" || user.Password != "123456" {
		c.HTML(http.StatusOK, "adminlogin.html", gin.H{
			"Errors": "Username and Password is incorrect",
		})
		return
	}

	session := sessions.Default(c)
	session.Set("username", user.Name)
	session.Save()

	c.Redirect(http.StatusSeeOther, "/adminpanel")
}

// func (ctrl *UserControls) Adminpanel(c *gin.Context) {
// 	session := sessions.Default(c)
// 	username := session.Get("username")
// 	if username == nil {
// 		c.Redirect(http.StatusSeeOther, "/adminloginpage")
// 		return
// 	}
// 	var temp_user []models.Users
// 	result := ctrl.DB.Find(&temp_user)

// 	if result.Error != nil {
// 		c.Redirect(http.StatusSeeOther, "/adminloginpage")
// 	} else {
// 		c.HTML(http.StatusOK, "admin.html", gin.H{
// 			"temp_user": temp_user,
// 		})
// 	}
// }

func (ctrl *UserControls) Adminpanel(c *gin.Context) {
	session := sessions.Default(c)
	username := session.Get("username")
	if username == nil {
		c.Redirect(http.StatusSeeOther, "/adminloginpage")
		return
	}
	var tempUser []models.Users
	// Fetch both soft-deleted and active users
	result := ctrl.DB.Find(&tempUser)

	if result.Error != nil {
		c.Redirect(http.StatusSeeOther, "/adminloginpage")
	} else {
		c.HTML(http.StatusOK, "admin.html", gin.H{
			"temp_user": tempUser,
		})
	}
}

// func (ctrl *UserControls) Delete(c *gin.Context) {
// 	session := sessions.Default(c)
// 	username := session.Get("username")
// 	if username == nil {
// 		c.Redirect(http.StatusSeeOther, "/adminloginpage")
// 		return
// 	}
// 	delete_id := c.PostForm("id")
// 	fmt.Println(delete_id)
// 	var temp_user models.Users
// 	ctrl.DB.Delete(&temp_user, delete_id)
// 	c.Redirect(http.StatusSeeOther, "/adminpanel")
// }

func (ctrl *UserControls) SoftDelete(c *gin.Context) {
	session := sessions.Default(c)
	username := session.Get("username")
	if username == nil {
		c.Redirect(http.StatusSeeOther, "/adminloginpage")
		return
	}
	deleteID := c.PostForm("id")
	var tempUser models.Users
	// Soft delete by updating the Deleted field
	ctrl.DB.Model(&tempUser).Where("id = ?", deleteID).Update("deleted", true)
	c.Redirect(http.StatusSeeOther, "/adminpanel")
}

// Permanent delete a user
func (ctrl *UserControls) PermanentDelete(c *gin.Context) {
	session := sessions.Default(c)
	username := session.Get("username")
	if username == nil {
		c.Redirect(http.StatusSeeOther, "/adminloginpage")
		return
	}
	deleteID := c.PostForm("id")
	var tempUser models.Users
	// Permanent delete by removing the record from the database
	ctrl.DB.Where("id = ?", deleteID).Delete(&tempUser)
	c.Redirect(http.StatusSeeOther, "/adminpanel")
}

func (ctrl *UserControls) Search(c *gin.Context) {

	session := sessions.Default(c)
	username := session.Get("username")
	if username == nil {
		c.Redirect(http.StatusSeeOther, "/adminloginpage")
		return
	}
	search_uname := c.Query("username")
	var temp_user []models.Users
	result := ctrl.DB.Where("user_name LIKE ?", "%"+search_uname+"%").Find(&temp_user)
	if result.Error != nil {
		c.Redirect(http.StatusSeeOther, "/adminpanel")

	} else {
		c.HTML(http.StatusOK, "admin.html", gin.H{
			"temp_user": temp_user,
		})

	}

}

func (ctrl *UserControls) Adminedit(c *gin.Context) {
	session := sessions.Default(c)
	username := session.Get("username")
	if username == nil {
		c.Redirect(http.StatusSeeOther, "/adminloginpage")
		return
	}
	id := c.PostForm("edit")
	var temp_user models.Users
	ctrl.DB.First(&temp_user, id)
	c.HTML(http.StatusOK, "edit.html", gin.H{
		"temp_user": temp_user,
	})
}

func (ctrl *UserControls) Admineditsave(c *gin.Context) {
	session := sessions.Default(c)
	username := session.Get("username")
	if username == nil {
		c.Redirect(http.StatusSeeOther, "/adminloginpage")
		return
	}
	id := c.PostForm("id")
	var user models.Users
	ctrl.DB.First(&user, id)

	user.First_Name = c.PostForm("firstname")
	user.Last_Name = c.PostForm("lastname")
	user.UserName = c.PostForm("username")
	user.Email = c.PostForm("email")
	user.Password = c.PostForm("password")

	ctrl.DB.Save(&user)

	c.Redirect(http.StatusSeeOther, "/adminpanel")
}

func (ctrl *UserControls) Admincreate(c *gin.Context) {
	session := sessions.Default(c)
	username := session.Get("username")
	if username == nil {
		c.Redirect(http.StatusSeeOther, "/adminloginpage")
		return
	}
	c.HTML(http.StatusOK, "admincreate.html", nil)
}

func (ctrl *UserControls) Admincreated(c *gin.Context) {
	session := sessions.Default(c)
	username := session.Get("username")
	if username == nil {
		c.Redirect(http.StatusSeeOther, "/adminloginpage")
		return
	}
	var user models.Users
	user.First_Name = c.PostForm("firstname")
	user.Last_Name = c.PostForm("lastname")
	user.UserName = c.PostForm("username")
	user.Email = c.PostForm("email")
	user.Password = c.PostForm("password")

	// Hash the password before storing it in the database
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		// Handle error
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"Message": "Error hashing password",
		})
		return
	}
	user.Password = string(hashedPassword)

	ctrl.DB.Create(&user)
	c.Redirect(http.StatusSeeOther, "/adminpanel")
}

func (ctrl *UserControls) Logoutadmin(c *gin.Context) {
	session := sessions.Default(c)
	session.Delete("username")
	session.Save()
	c.Redirect(http.StatusSeeOther, "/adminloginpage")
}
